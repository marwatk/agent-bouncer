// Package examples embeds the example config and filters for `bouncer init`.
package examples

import "embed"

//go:embed config.yaml *.test.yaml filters/*.ts filters/*.test.yaml
var FS embed.FS
