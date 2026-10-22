package approval

import (
	"strings"
	"testing"
)

func TestDisplay(t *testing.T) {
	got := Display("GET /x\x1b[2K\rGET /harmless‮​", 200)
	if strings.ContainsAny(got, "\x1b\r‮​") || !strings.Contains(got, `\u001b`) {
		t.Fatalf("control characters survived: %q", got)
	}
	long := Display(strings.Repeat("a", 500), 100)
	if !strings.HasSuffix(long, "… [400 more characters]") || len([]rune(long)) > 130 {
		t.Fatalf("not truncated: %q", long)
	}
	if Display("ssh agent@sandbox exec: ls -la", 200) != "ssh agent@sandbox exec: ls -la" {
		t.Fatal("plain text altered")
	}
}
