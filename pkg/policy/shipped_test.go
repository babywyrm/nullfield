package policy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Every policy the repository ships, as a file or inside a ConfigMap, must
// load. A shipped example the loader refuses is either broken or teaching
// someone a field that does nothing.
func TestEveryShippedPolicyLoads(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "plans", "node_modules", "templates": // templates: Helm, not YAML yet
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		for {
			var doc map[string]any
			if err := dec.Decode(&doc); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Logf("%s: skipped, not YAML: %v", rel, err)
				}
				break
			}
			switch doc["kind"] {
			case "NullfieldPolicy":
				b, _ := yaml.Marshal(doc)
				found++
				if _, err := ParseSpec(b); err != nil {
					t.Errorf("%s: %v", rel, err)
				}
			case "ConfigMap":
				data, _ := doc["data"].(map[string]any)
				for key, v := range data {
					if s, ok := v.(string); ok && strings.Contains(s, "kind: NullfieldPolicy") {
						found++
						if _, err := ParseSpec([]byte(s)); err != nil {
							t.Errorf("%s (%s): %v", rel, key, err)
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 10 {
		t.Fatalf("found only %d policies; the walk is not reaching the repository", found)
	}
}
