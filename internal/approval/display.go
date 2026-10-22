package approval

import (
	"fmt"
	"strings"
	"unicode"
)

// Display makes request-derived text safe to show a human deciding on it:
// control characters, terminal escapes and invisible formatting (bidi
// overrides, zero-width characters) are shown escaped rather than
// interpreted, and text beyond max runes is cut off with a visible marker,
// so a request can't disguise or bury what's being approved.
func Display(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == max {
			fmt.Fprintf(&b, "… [%d more characters]", len([]rune(s))-max)
			break
		}
		n++
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}
