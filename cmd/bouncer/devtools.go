package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marwatk/agent-bouncer/examples"
	"github.com/marwatk/agent-bouncer/internal/testrunner"
	"github.com/marwatk/agent-bouncer/types"
)

func testCmd() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "test [paths...]",
		Short: "Run *.test.yaml specs against filters and configs",
		Long: `Runs policy tests offline with a mocked upstream. Each spec targets one filter
(filter: + filter_config:) or a profile of a config file (config: + profile:).
Paths may be files or directories (searched recursively); default ".".`,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"."}
			}
			files, err := testrunner.Find(args)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return errors.New("no *.test.yaml files found")
			}
			passed, failed := 0, 0
			for _, f := range files {
				results, err := testrunner.RunFile(f)
				if err != nil {
					fmt.Printf("ERROR %s\n  %v\n", f, err)
					failed++
					continue
				}
				fileFailed := false
				for _, r := range results {
					if r.Passed {
						passed++
					} else {
						failed++
						fileFailed = true
					}
				}
				status := "ok   "
				if fileFailed {
					status = "FAIL "
				}
				fmt.Printf("%s %s (%d cases)\n", status, f, len(results))
				for _, r := range results {
					switch {
					case !r.Passed:
						fmt.Printf("  ✗ %s\n    %s\n", r.Name, r.Message)
					case verbose:
						fmt.Printf("  ✓ %s\n", r.Name)
					}
				}
			}
			fmt.Printf("\n%d passed, %d failed\n", passed, failed)
			if failed > 0 {
				return exitCode(1)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "list passing cases too")
	return cmd
}

func initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter config, example filters and type definitions",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			dir := filepath.Dir(configPath)
			if _, err := os.Stat(configPath); err == nil && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", configPath)
			}
			if err := os.MkdirAll(filepath.Join(dir, "filters"), 0o755); err != nil {
				return err
			}
			err := fs.WalkDir(examples.FS, ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				data, err := examples.FS.ReadFile(p)
				if err != nil {
					return err
				}
				dst := filepath.Join(dir, filepath.FromSlash(p))
				if p == "config.yaml" {
					dst = configPath
				}
				return os.WriteFile(dst, data, 0o644)
			})
			if err != nil {
				return err
			}
			// Types live next to the filters so editors resolve "bouncer".
			if err := os.WriteFile(filepath.Join(dir, "filters", "bouncer.d.ts"), types.BouncerDTS, 0o644); err != nil {
				return err
			}
			tsconfig := `{
  "compilerOptions": {"target": "ES2020", "module": "ESNext", "moduleResolution": "Bundler",
                      "lib": ["ES2020"], "types": [], "strict": true, "noEmit": true},
  "include": ["*.ts"]
}
`
			if err := os.WriteFile(filepath.Join(dir, "filters", "tsconfig.json"), []byte(tsconfig), 0o644); err != nil {
				return err
			}
			fmt.Printf(`wrote %s and example filters in %s

next:
  1. edit %s (replace mygroup/myproject, credential sources, ...)
  2. store secrets:        bouncer cred set gitlab
  3. start the daemon:     bouncer serve
  4. trust the CA (once):  bouncer ca install
  5. run an agent:         bouncer exec -- claude
  tests:                   bouncer test %s
`, configPath, filepath.Join(dir, "filters"), configPath, shortPath(dir))
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}

func shortPath(p string) string {
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, home) {
		return "~" + p[len(home):]
	}
	return p
}
