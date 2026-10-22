package testrunner

import "testing"

// TestExamples runs every spec under examples/, so `go test ./...` keeps
// the shipped filters and config honest.
func TestExamples(t *testing.T) {
	files, err := Find([]string{"../../examples"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d spec files", len(files))
	}
	for _, f := range files {
		results, err := RunFile(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, r := range results {
			if !r.Passed {
				t.Errorf("%s: %s: %s", f, r.Name, r.Message)
			}
		}
	}
}
