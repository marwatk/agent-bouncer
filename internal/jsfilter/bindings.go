package jsfilter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dop251/goja"

	"github.com/marwatk/agent-bouncer/internal/chain"
)

const (
	kindKey = "__bouncer"
	respKey = "__bouncer_response"
)

// installHost defines globalThis.__bouncer_host, backing the "bouncer" module.
func (i *instance) installHost() error {
	vm := i.vm
	host := vm.NewObject()

	host.Set("deny", func(call goja.FunctionCall) goja.Value {
		o := vm.NewObject()
		o.Set(kindKey, "deny")
		reason := "denied"
		if a := call.Argument(0); !goja.IsUndefined(a) {
			reason = a.String()
		}
		o.Set("reason", reason)
		o.Set("status", 403)
		if opts, ok := call.Argument(1).(*goja.Object); ok {
			if s := opts.Get("status"); s != nil && !goja.IsUndefined(s) {
				o.Set("status", s)
			}
		}
		return o
	})

	host.Set("respond", func(call goja.FunctionCall) goja.Value {
		o := vm.NewObject()
		o.Set(kindKey, "respond")
		o.Set("status", call.Argument(0))
		o.Set("body", call.Argument(1))
		o.Set("headers", call.Argument(2))
		return o
	})

	host.Set("ask", func(call goja.FunctionCall) goja.Value {
		prompt := call.Argument(0).String()
		var key string
		var timeout time.Duration
		if opts, ok := call.Argument(1).(*goja.Object); ok {
			if k := opts.Get("key"); k != nil && !goja.IsUndefined(k) {
				key = k.String()
			}
			if t := opts.Get("timeout"); t != nil && !goja.IsUndefined(t) {
				timeout = parseTTL(t)
			}
		}
		req := i.cur
		env := i.f.opts.Env
		if req == nil || env.Approver == nil {
			i.log("ask() denied: no approver configured", nil)
			return i.resolved(vm.ToValue(false))
		}
		ctx := req.Ctx
		if timeout > 0 {
			var cancel func()
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		i.wd.pause()
		ok, err := env.Approver.Ask(ctx, chain.AskRequest{Session: req.Session, Filter: i.f.name, Prompt: prompt, Key: key, Request: req.Describe()})
		i.wd.resume()
		if err != nil {
			i.log("ask() failed: "+err.Error(), nil)
		}
		return i.resolved(vm.ToValue(ok))
	})

	host.Set("log", func(call goja.FunctionCall) goja.Value {
		var fields map[string]any
		if o, ok := call.Argument(1).(*goja.Object); ok {
			fields, _ = o.Export().(map[string]any)
		}
		i.log(call.Argument(0).String(), fields)
		return goja.Undefined()
	})

	kvObj := vm.NewObject()
	store := i.f.opts.KV
	ns := i.f.name
	kvObj.Set("get", func(k string) goja.Value {
		if store == nil {
			return goja.Undefined()
		}
		v, ok := store.Get(ns, k)
		if !ok {
			return goja.Undefined()
		}
		return i.plain(v)
	})
	kvObj.Set("set", func(call goja.FunctionCall) goja.Value {
		if store != nil {
			store.Set(ns, call.Argument(0).String(), exportPlain(call.Argument(1)), ttlOpt(call.Argument(2)))
		}
		return goja.Undefined()
	})
	kvObj.Set("incr", func(call goja.FunctionCall) goja.Value {
		by := 1.0
		if o, ok := call.Argument(1).(*goja.Object); ok {
			if b := o.Get("by"); b != nil && !goja.IsUndefined(b) {
				by = b.ToFloat()
			}
		}
		if store == nil {
			return vm.ToValue(by)
		}
		return vm.ToValue(store.Incr(ns, call.Argument(0).String(), by, ttlOpt(call.Argument(1))))
	})
	kvObj.Set("delete", func(k string) {
		if store != nil {
			store.Delete(ns, k)
		}
	})
	kvObj.Set("keys", func(call goja.FunctionCall) goja.Value {
		if store == nil {
			return vm.NewArray()
		}
		prefix := ""
		if a := call.Argument(0); !goja.IsUndefined(a) {
			prefix = a.String()
		}
		return i.plain(store.Keys(ns, prefix))
	})
	host.Set("kv", kvObj)

	if err := vm.Set("__bouncer_host", host); err != nil {
		return err
	}
	console := vm.NewObject()
	logFn := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for j, a := range call.Arguments {
			if o, ok := a.(*goja.Object); ok && o.ClassName() != "Function" {
				if s, err := i.jsonStr(goja.Undefined(), a); err == nil && !goja.IsUndefined(s) {
					parts[j] = s.String()
					continue
				}
			}
			parts[j] = a.String()
		}
		i.log(strings.Join(parts, " "), nil)
		return goja.Undefined()
	}
	for _, n := range []string{"log", "info", "warn", "error", "debug"} {
		console.Set(n, logFn)
	}
	return vm.Set("console", console)
}

func (i *instance) log(msg string, fields map[string]any) {
	if l := i.f.opts.Env.Log; l != nil {
		l(i.f.name, msg, fields)
	}
}

// context is the third argument to hooks.
func (i *instance) context(req *chain.Request) goja.Value {
	o := i.vm.NewObject()
	o.Set("name", i.f.name)
	cfg := i.f.opts.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	o.Set("config", i.plain(cfg))
	return o
}

func (i *instance) resolved(v goja.Value) goja.Value {
	p, resolve, _ := i.vm.NewPromise()
	resolve(v)
	return i.vm.ToValue(p)
}

func (i *instance) rejected(err error) goja.Value {
	p, _, reject := i.vm.NewPromise()
	reject(i.vm.NewGoError(err))
	return i.vm.ToValue(p)
}

// blocking runs a host operation that waits on something outside the
// filter (upstream, a human) with the CPU watchdog paused, returning a
// settled promise.
func (i *instance) blocking(fn func() (goja.Value, error)) goja.Value {
	return i.hostCall(true, fn)
}

// hostCall runs a host operation, pausing the watchdog only if it may wait
// on I/O. Work served from memory counts against the filter's budget, so a
// loop of cheap host calls can't run unbounded.
func (i *instance) hostCall(mayWait bool, fn func() (goja.Value, error)) goja.Value {
	if mayWait {
		i.wd.pause()
	}
	v, err := fn()
	if mayWait {
		i.wd.resume()
	}
	if err != nil {
		return i.rejected(err)
	}
	return i.resolved(v)
}

// plain converts a Go value to a native JS value via JSON, so arrays and
// objects behave exactly like JS ones.
func (i *instance) plain(v any) goja.Value {
	b, err := json.Marshal(v)
	if err != nil {
		return goja.Undefined()
	}
	out, err := i.jsonParse(goja.Undefined(), i.vm.ToValue(string(b)))
	if err != nil {
		return goja.Undefined()
	}
	return out
}

// exportPlain converts a JS value to JSON-compatible Go data.
func exportPlain(v goja.Value) any {
	if v == nil || goja.IsUndefined(v) {
		return nil
	}
	b, err := json.Marshal(v.Export())
	if err != nil {
		return nil
	}
	var out any
	json.Unmarshal(b, &out)
	return out
}

func ttlOpt(v goja.Value) time.Duration {
	o, ok := v.(*goja.Object)
	if !ok {
		return 0
	}
	t := o.Get("ttl")
	if t == nil || goja.IsUndefined(t) {
		return 0
	}
	return parseTTL(t)
}

// parseTTL accepts a duration string ("1h") or a number of seconds.
func parseTTL(v goja.Value) time.Duration {
	if s, ok := v.Export().(string); ok {
		d, _ := time.ParseDuration(s)
		return d
	}
	return time.Duration(v.ToFloat() * float64(time.Second))
}

func (i *instance) bytesValue(b []byte) goja.Value {
	o, err := i.vm.New(i.u8, i.vm.ToValue(i.vm.NewArrayBuffer(b)))
	if err != nil {
		return goja.Undefined()
	}
	return o
}

func toBytes(i *instance, v goja.Value) ([]byte, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, nil
	}
	switch x := v.Export().(type) {
	case string:
		return []byte(x), nil
	case []byte:
		return x, nil
	case goja.ArrayBuffer:
		return x.Bytes(), nil
	}
	s, err := i.jsonStr(goja.Undefined(), v)
	if err != nil {
		return nil, err
	}
	return []byte(s.String()), nil
}

func textOf(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

// headers wraps an http.Header with a Fetch-like API.
func (i *instance) headers(h http.Header) *goja.Object {
	o := i.vm.NewObject()
	o.Set("get", func(name string) goja.Value {
		v := h.Values(name)
		if len(v) == 0 {
			return goja.Null()
		}
		return i.vm.ToValue(strings.Join(v, ", "))
	})
	o.Set("getAll", func(name string) goja.Value { return i.plain(h.Values(name)) })
	o.Set("has", func(name string) bool { return len(h.Values(name)) > 0 })
	o.Set("set", func(name, value string) { h.Set(name, value) })
	o.Set("append", func(name, value string) { h.Add(name, value) })
	o.Set("delete", func(name string) { h.Del(name) })
	o.Set("entries", func() goja.Value {
		var out [][2]string
		for k, vs := range h {
			for _, v := range vs {
				out = append(out, [2]string{strings.ToLower(k), v})
			}
		}
		return i.plain(out)
	})
	return o
}

// body wraps a chain.Body.
func (i *instance) body(b *chain.Body) *goja.Object {
	if b == nil {
		b = chain.BytesBody(nil)
	}
	o := i.vm.NewObject()
	o.Set("peek", func(n int) goja.Value {
		return i.hostCall(!b.Buffered(n), func() (goja.Value, error) {
			p, err := b.Peek(n)
			return i.bytesValue(p), err
		})
	})
	o.Set("peekText", func(n int) goja.Value {
		return i.hostCall(!b.Buffered(n), func() (goja.Value, error) {
			p, err := b.Peek(n)
			return i.vm.ToValue(textOf(p)), err
		})
	})
	o.Set("bytes", func() goja.Value {
		return i.hostCall(!b.Complete(), func() (goja.Value, error) {
			p, err := b.ReadAll()
			return i.bytesValue(p), err
		})
	})
	o.Set("text", func() goja.Value {
		return i.hostCall(!b.Complete(), func() (goja.Value, error) {
			p, err := b.ReadAll()
			return i.vm.ToValue(textOf(p)), err
		})
	})
	o.Set("json", func() goja.Value {
		return i.hostCall(!b.Complete(), func() (goja.Value, error) {
			p, err := b.ReadAll()
			if err != nil {
				return nil, err
			}
			return i.jsonParse(goja.Undefined(), i.vm.ToValue(string(p)))
		})
	})
	o.Set("set", func(v goja.Value) error {
		data, err := toBytes(i, v)
		if err != nil {
			return err
		}
		b.Set(data)
		return nil
	})
	return o
}

func (i *instance) wrapRequest(req *chain.Request) *goja.Object {
	vm := i.vm
	o := vm.NewObject()
	o.Set("transport", req.Transport)
	o.Set("host", req.Host())
	o.Set("service", req.Service)
	o.Set("profile", req.Profile)
	if req.Session != nil {
		o.Set("session", i.plain(req.Session))
	} else {
		o.Set("session", goja.Null())
	}
	o.Set("describe", func() string { return req.Describe() })

	if req.Transport == chain.TransportHTTP {
		o.Set("method", req.Method)
		o.Set("url", req.URL.String())
		o.Set("path", req.Path())
		o.Set("rawPath", req.RawPath())
		q := req.URL.Query()
		qo := vm.NewObject()
		qo.Set("get", func(k string) goja.Value {
			if !q.Has(k) {
				return goja.Null()
			}
			return vm.ToValue(q.Get(k))
		})
		qo.Set("getAll", func(k string) goja.Value { return i.plain(q[k]) })
		qo.Set("has", func(k string) bool { return q.Has(k) })
		o.Set("query", qo)
		o.Set("headers", i.headers(req.Header))
		o.Set("body", i.body(req.Body))
		o.Set("graphql", func() goja.Value {
			return i.hostCall(!bodyComplete(req), func() (goja.Value, error) {
				ops, err := req.GraphQL()
				if err != nil {
					return nil, err
				}
				if ops == nil {
					return goja.Null(), nil
				}
				return i.plain(ops), nil
			})
		})
	} else {
		o.Set("ssh", i.plain(req.SSH))
	}

	if g := req.Git(); g != nil {
		go_ := vm.NewObject()
		go_.Set("service", g.Service)
		go_.Set("repo", g.Repo)
		push := func() (goja.Value, error) {
			p, err := req.Push()
			if err != nil {
				return nil, err
			}
			if p == nil {
				return goja.Null(), nil
			}
			return i.plain(p), nil
		}
		go_.Set("push", func() goja.Value { return i.hostCall(!bodyComplete(req), push) })
		go_.Set("refUpdates", func() goja.Value {
			return i.hostCall(!bodyComplete(req), func() (goja.Value, error) {
				p, err := req.Push()
				if err != nil {
					return nil, err
				}
				if p == nil || p.Updates == nil {
					return vm.NewArray(), nil
				}
				return i.plain(p.Updates), nil
			})
		})
		o.Set("git", go_)
	} else {
		o.Set("git", goja.Null())
	}
	return o
}

func bodyComplete(req *chain.Request) bool { return req.Body == nil || req.Body.Complete() }

func (i *instance) nextFunc(req *chain.Request, next chain.Handler) goja.Value {
	called := false
	return i.vm.ToValue(func(goja.FunctionCall) goja.Value {
		if called {
			return i.rejected(fmt.Errorf("next() called more than once"))
		}
		called = true
		return i.blocking(func() (goja.Value, error) {
			resp, err := next(req)
			if err != nil {
				return nil, err
			}
			return i.wrapResponse(resp), nil
		})
	})
}

func (i *instance) wrapResponse(resp *chain.Response) goja.Value {
	vm := i.vm
	o := vm.NewObject()
	o.DefineDataProperty(respKey, vm.ToValue(resp), goja.FLAG_FALSE, goja.FLAG_FALSE, goja.FLAG_FALSE)
	o.DefineAccessorProperty("status", vm.ToValue(func() int { return resp.Status }), nil, goja.FLAG_FALSE, goja.FLAG_TRUE)
	o.Set("setStatus", func(s int) { resp.Status = s })
	if resp.Header == nil {
		resp.Header = http.Header{}
	}
	o.Set("headers", i.headers(resp.Header))
	if resp.Body == nil {
		resp.Body = chain.BytesBody(nil)
	}
	o.Set("body", i.body(resp.Body))
	if d := resp.Denial; d != nil {
		o.Set("denied", i.plain(map[string]string{"by": d.By, "reason": d.Reason}))
	} else {
		o.Set("denied", goja.Null())
	}
	return o
}

func (i *instance) syntheticResponse(o *goja.Object) (*chain.Response, error) {
	status := int(o.Get("status").ToInteger())
	if status < 100 || status > 599 {
		return nil, fmt.Errorf("respond(): invalid status %d", status)
	}
	body, err := toBytes(i, o.Get("body"))
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	if ho, ok := o.Get("headers").(*goja.Object); ok {
		for _, k := range ho.Keys() {
			h.Set(k, ho.Get(k).String())
		}
	}
	if h.Get("Content-Type") == "" && len(body) > 0 {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	return &chain.Response{Status: status, Header: h, Body: chain.BytesBody(body)}, nil
}
