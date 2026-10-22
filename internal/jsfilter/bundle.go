// Package jsfilter runs TypeScript/JavaScript filters in embedded goja VMs.
package jsfilter

import (
	"fmt"
	"strings"

	"github.com/evanw/esbuild/pkg/api"
)

const globalName = "__bouncer_filter"

// bouncerModule is the virtual "bouncer" import that filters use.
const bouncerModule = `
const h = globalThis.__bouncer_host;
export const defineFilter = (d) => d;
export const deny = h.deny;
export const respond = h.respond;
export const ask = h.ask;
export const log = h.log;
export const kv = h.kv;
export default { defineFilter, deny, respond, ask, log, kv };
`

var bouncerPlugin = api.Plugin{
	Name: "bouncer",
	Setup: func(b api.PluginBuild) {
		b.OnResolve(api.OnResolveOptions{Filter: `^bouncer$`}, func(api.OnResolveArgs) (api.OnResolveResult, error) {
			return api.OnResolveResult{Path: "bouncer", Namespace: "bouncer"}, nil
		})
		b.OnLoad(api.OnLoadOptions{Filter: `.*`, Namespace: "bouncer"}, func(api.OnLoadArgs) (api.OnLoadResult, error) {
			src := bouncerModule
			return api.OnLoadResult{Contents: &src, Loader: api.LoaderJS}, nil
		})
	},
}

// Bundle compiles a filter entry point (and its relative or node_modules
// imports) into a single script for goja.
func Bundle(path string) (string, error) {
	res := api.Build(api.BuildOptions{
		EntryPoints:    []string{path},
		Bundle:         true,
		Write:          false,
		Format:         api.FormatIIFE,
		GlobalName:     globalName,
		Platform:       api.PlatformNeutral,
		MainFields:     []string{"module", "main"},
		Target:         api.ES2017,
		Sourcemap:      api.SourceMapInline,
		SourcesContent: api.SourcesContentExclude,
		Plugins:        []api.Plugin{bouncerPlugin},
		LogLevel:       api.LogLevelSilent,
	})
	if len(res.Errors) > 0 {
		var msgs []string
		for _, m := range res.Errors {
			if m.Location != nil {
				msgs = append(msgs, fmt.Sprintf("%s:%d:%d: %s", m.Location.File, m.Location.Line, m.Location.Column, m.Text))
			} else {
				msgs = append(msgs, m.Text)
			}
		}
		return "", fmt.Errorf("compiling %s:\n  %s", path, strings.Join(msgs, "\n  "))
	}
	return string(res.OutputFiles[0].Contents), nil
}
