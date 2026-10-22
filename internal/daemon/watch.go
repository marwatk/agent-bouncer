package daemon

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// watch reloads the config when it or any referenced filter changes. It
// watches directories rather than files so editors that replace files on
// save are handled.
func (d *Daemon) watch() (func(), error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dirs := map[string]bool{}
	refresh := func() {
		want := map[string]bool{filepath.Dir(d.Config().Path): true}
		for _, f := range d.filterPaths() {
			want[filepath.Dir(f)] = true
		}
		for dir := range want {
			if !dirs[dir] {
				if w.Add(dir) == nil {
					dirs[dir] = true
				}
			}
		}
	}
	refresh()
	done := make(chan struct{})
	go func() {
		var timer <-chan time.Time
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 && relevant(ev.Name) {
					timer = time.After(250 * time.Millisecond)
				}
			case <-timer:
				timer = nil
				if d.Reload() == nil {
					refresh()
				}
			case <-w.Errors:
			case <-done:
				return
			}
		}
	}()
	return func() { close(done); w.Close() }, nil
}

func relevant(name string) bool {
	switch filepath.Ext(name) {
	case ".yaml", ".yml", ".ts", ".js", ".mts", ".mjs", ".json":
		return true
	}
	return false
}

func (d *Daemon) filterPaths() []string {
	cfg := d.Config()
	var out []string
	for _, p := range cfg.Profiles {
		for _, f := range p.Filters {
			out = append(out, f.Path)
		}
		for _, s := range p.Services {
			for _, f := range s.Filters {
				out = append(out, f.Path)
			}
		}
		for _, s := range p.SSH {
			for _, f := range s.Filters {
				out = append(out, f.Path)
			}
		}
	}
	return out
}
