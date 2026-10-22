package jsfilter

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	"github.com/marwatk/agent-bouncer/internal/chain"
	"github.com/marwatk/agent-bouncer/internal/kv"
)

// DefaultTimeout bounds the CPU time (excluding time blocked in host calls
// like next() or ask()) a single filter invocation may use.
const DefaultTimeout = 2 * time.Second

const poolSize = 8

// Options configure a loaded filter.
type Options struct {
	Path    string
	Config  map[string]any
	Timeout time.Duration
	Env     *chain.Env
	KV      *kv.Store
}

// Filter is a compiled JS filter. Each concurrent request gets its own VM
// from a pool, so module-level variables are per-VM, not shared: use kv for
// state that must persist across requests.
type Filter struct {
	name  string
	opts  Options
	prog  *goja.Program
	pool  chan *instance
	hooks struct{ request, response, ssh bool }
}

// Load bundles, compiles and validates a filter.
func Load(opts Options) (*Filter, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Env == nil {
		opts.Env = &chain.Env{}
	}
	code, err := Bundle(opts.Path)
	if err != nil {
		return nil, err
	}
	prog, err := goja.Compile(opts.Path, code, false)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.Path, err)
	}
	f := &Filter{opts: opts, prog: prog, pool: make(chan *instance, poolSize)}
	f.name = strings.TrimSuffix(filepath.Base(opts.Path), filepath.Ext(opts.Path))
	inst, err := f.newInstance()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", opts.Path, err)
	}
	if n := inst.def.Get("name"); n != nil && !goja.IsUndefined(n) {
		f.name = n.String()
	}
	f.hooks.request = inst.onRequest != nil
	f.hooks.response = inst.onResponse != nil
	f.hooks.ssh = inst.onSSH != nil
	if !f.hooks.request && !f.hooks.response && !f.hooks.ssh {
		return nil, fmt.Errorf("%s: filter defines none of onRequest, onResponse, onSSH", opts.Path)
	}
	f.put(inst)
	return f, nil
}

func (f *Filter) Name() string { return f.name }

// Path is the filter's source file.
func (f *Filter) Path() string { return f.opts.Path }

func (f *Filter) Handle(req *chain.Request, next chain.Handler) (*chain.Response, error) {
	switch req.Transport {
	case chain.TransportSSH:
		if !f.hooks.ssh {
			return next(req)
		}
	default:
		if !f.hooks.request && !f.hooks.response {
			return next(req)
		}
	}
	inst, err := f.get()
	if err != nil {
		return nil, err
	}
	resp, err := inst.run(req, next)
	if inst.broken {
		return resp, err
	}
	f.put(inst)
	return resp, err
}

func (f *Filter) get() (*instance, error) {
	select {
	case i := <-f.pool:
		return i, nil
	default:
		return f.newInstance()
	}
}

func (f *Filter) put(i *instance) {
	select {
	case f.pool <- i:
	default:
	}
}

// instance is one VM with the filter loaded.
type instance struct {
	f          *Filter
	vm         *goja.Runtime
	def        *goja.Object
	onRequest  goja.Callable
	onResponse goja.Callable
	onSSH      goja.Callable
	u8         goja.Value
	jsonParse  goja.Callable
	jsonStr    goja.Callable
	wd         watchdog
	broken     bool

	// cur is the request being handled; host functions consult it.
	cur *chain.Request
}

func (f *Filter) newInstance() (*instance, error) {
	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))
	inst := &instance{f: f, vm: vm}
	inst.wd.vm = vm
	if err := inst.installHost(); err != nil {
		return nil, err
	}
	if _, err := vm.RunProgram(f.prog); err != nil {
		return nil, err
	}
	mod := vm.Get(globalName)
	if mod == nil || goja.IsUndefined(mod) {
		return nil, errors.New("filter produced no module")
	}
	def := mod.ToObject(vm).Get("default")
	if def == nil || goja.IsUndefined(def) || goja.IsNull(def) {
		return nil, errors.New("filter has no default export; use `export default defineFilter({...})`")
	}
	inst.def = def.ToObject(vm)
	for name, dst := range map[string]*goja.Callable{"onRequest": &inst.onRequest, "onResponse": &inst.onResponse, "onSSH": &inst.onSSH} {
		v := inst.def.Get(name)
		if v == nil || goja.IsUndefined(v) {
			continue
		}
		fn, ok := goja.AssertFunction(v)
		if !ok {
			return nil, fmt.Errorf("%s must be a function", name)
		}
		*dst = fn
	}
	inst.u8 = vm.Get("Uint8Array")
	j := vm.Get("JSON").ToObject(vm)
	inst.jsonParse, _ = goja.AssertFunction(j.Get("parse"))
	inst.jsonStr, _ = goja.AssertFunction(j.Get("stringify"))
	return inst, nil
}

// run invokes the filter's hooks for one request.
func (i *instance) run(req *chain.Request, next chain.Handler) (resp *chain.Response, err error) {
	i.cur = req
	i.vm.ClearInterrupt()
	i.wd.start(i.f.opts.Timeout)
	defer func() {
		i.wd.stop()
		i.cur = nil
		var ie *goja.InterruptedError
		if errors.As(err, &ie) {
			i.broken = true
			err = fmt.Errorf("exceeded %s CPU budget", i.f.opts.Timeout)
		}
	}()

	jsReq := i.wrapRequest(req)
	jsCtx := i.context(req)

	hook := i.onRequest
	if req.Transport == chain.TransportSSH {
		hook = i.onSSH
	}
	if hook == nil {
		i.wd.pause()
		resp, err = next(req)
		i.wd.resume()
		if err != nil {
			return nil, err
		}
	} else {
		v, err := hook(i.def, jsReq, i.nextFunc(req, next), jsCtx)
		if err != nil {
			return nil, err
		}
		v, err = i.settle(v)
		if err != nil {
			return nil, err
		}
		resp, err = i.toResponse(v, nil)
		if err != nil {
			return nil, err
		}
	}

	if i.onResponse != nil && req.Transport == chain.TransportHTTP {
		v, err := i.onResponse(i.def, i.wrapResponse(resp), jsReq, jsCtx)
		if err != nil {
			return nil, err
		}
		v, err = i.settle(v)
		if err != nil {
			return nil, err
		}
		return i.toResponse(v, resp)
	}
	return resp, nil
}

// settle unwraps a promise returned by a hook. Host calls are synchronous,
// so by the time the outermost call returns the promise must have settled.
func (i *instance) settle(v goja.Value) (goja.Value, error) {
	p, ok := v.Export().(*goja.Promise)
	if !ok {
		return v, nil
	}
	switch p.State() {
	case goja.PromiseStateFulfilled:
		return p.Result(), nil
	case goja.PromiseStateRejected:
		return nil, jsError(i.vm, p.Result())
	default:
		return nil, errors.New("filter promise never settled (awaiting something bouncer doesn't provide?)")
	}
}

func jsError(vm *goja.Runtime, v goja.Value) error {
	if o, ok := v.(*goja.Object); ok {
		if st := o.Get("stack"); st != nil && !goja.IsUndefined(st) {
			return errors.New(st.String())
		}
	}
	return errors.New(v.String())
}

// toResponse converts a hook's return value. fallback (for onResponse) is
// used when the hook returns undefined.
func (i *instance) toResponse(v goja.Value, fallback *chain.Response) (*chain.Response, error) {
	if v == nil || goja.IsUndefined(v) || goja.IsNull(v) {
		if fallback != nil {
			return fallback, nil
		}
		return nil, errors.New("filter returned nothing; return next(req), deny(...), or respond(...)")
	}
	o, ok := v.(*goja.Object)
	if !ok {
		return nil, fmt.Errorf("filter returned %s; expected a response", v.String())
	}
	if rv := o.Get(respKey); rv != nil {
		if r, ok := rv.Export().(*chain.Response); ok && r != nil {
			return r, nil
		}
	}
	switch kind := o.Get(kindKey); {
	case kind == nil || goja.IsUndefined(kind):
	case kind.String() == "deny":
		reason := o.Get("reason").String()
		resp := chain.Deny(i.f.name, reason)
		if s := o.Get("status"); s != nil && s.ToInteger() >= 400 && s.ToInteger() < 600 {
			resp.Status, resp.Denial.Status = int(s.ToInteger()), int(s.ToInteger())
		}
		return resp, nil
	case kind.String() == "respond":
		return i.syntheticResponse(o)
	}
	return nil, errors.New("filter returned an object that is not a response; return next(req), deny(...), or respond(...)")
}

// watchdog interrupts the VM after a CPU budget, pausing while the filter is
// blocked in host calls.
type watchdog struct {
	vm        *goja.Runtime
	mu        sync.Mutex
	timer     *time.Timer
	remaining time.Duration
	started   time.Time
	paused    int
}

func (w *watchdog) start(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.remaining, w.paused, w.started = d, 0, time.Now()
	w.timer = time.AfterFunc(d, w.fire)
}

func (w *watchdog) fire() { w.vm.Interrupt("timeout") }

func (w *watchdog) pause() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.paused == 0 && w.timer != nil {
		w.timer.Stop()
		w.remaining -= time.Since(w.started)
	}
	w.paused++
}

func (w *watchdog) resume() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.paused--
	if w.paused == 0 {
		w.started = time.Now()
		w.timer = time.AfterFunc(max(w.remaining, time.Millisecond), w.fire)
	}
}

func (w *watchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
}
