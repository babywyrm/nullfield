// Package operations names what a call does to an integration, from data.
//
// One YAML file per target maps "METHOD /path" to a name such as repos.delete
// and the path parameters it acts on, so an integration is added by writing a
// file rather than code.
package operations

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrAmbiguous is a path on a mapped target that the map cannot read one way
// only. It is refused rather than left unnamed, so a rule on a name cannot be
// dodged by another spelling of the same path.
var ErrAmbiguous = errors.New("operations: ambiguous path")

// File is one target's map.
type File struct {
	Target     string      `yaml:"target"`
	Operations []Operation `yaml:"operations"`
}

// Operation names one method and path template. A {name} segment matches
// exactly one path segment and is returned as a parameter.
type Operation struct {
	Name   string `yaml:"name"`
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// Map resolves calls against every loaded target.
type Map struct {
	targets map[string][]Operation
}

// LoadDir loads every .yaml and .yml file in dir. A directory with no maps, or
// any map that does not validate, is an error.
func LoadDir(dir string) (*Map, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := &Map{targets: map[string][]Operation{}}
	for _, e := range entries {
		if ext := filepath.Ext(e.Name()); e.IsDir() || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := loadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if _, dup := m.targets[f.Target]; dup {
			return nil, fmt.Errorf("%s: target %s is mapped twice", path, f.Target)
		}
		m.targets[f.Target] = f.Operations
	}
	if len(m.targets) == 0 {
		return nil, fmt.Errorf("operations: no maps in %s", dir)
	}
	return m, nil
}

func loadFile(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, err
	}
	if f.Target == "" || f.Target != host(f.Target) {
		return nil, fmt.Errorf("target %q must be a lowercase host with no port", f.Target)
	}
	if len(f.Operations) == 0 {
		return nil, errors.New("no operations")
	}
	for i, op := range f.Operations {
		if err := op.validate(); err != nil {
			return nil, fmt.Errorf("operation %d: %w", i, err)
		}
	}
	return &f, nil
}

func (op Operation) validate() error {
	if op.Name == "" || op.Method == "" {
		return errors.New("name and method are required")
	}
	segs, ok := split(op.Path)
	if !ok {
		return fmt.Errorf("path %q must be absolute with no empty or dot segments", op.Path)
	}
	seen := map[string]bool{}
	for _, s := range segs {
		if p, ok := param(s); ok {
			if p == "" || seen[p] {
				return fmt.Errorf("path %q: parameters must be named once each", op.Path)
			}
			seen[p] = true
		}
	}
	return nil
}

// Resolve names an operation on target, as "METHOD /path" with any query.
// A target with no map, or a call its map does not list, has no name and no
// error.
func (m *Map) Resolve(target, operation string) (string, map[string]string, error) {
	ops, ok := m.targets[host(target)]
	if !ok {
		return "", nil, nil
	}
	method, path, _ := strings.Cut(operation, " ")
	path, _, _ = strings.Cut(path, "?")
	raw, ok := split(path)
	if !ok {
		return "", nil, ErrAmbiguous
	}
	segs := make([]string, len(raw))
	for i, s := range raw {
		d, err := url.PathUnescape(s)
		if err != nil || d == "." || d == ".." || strings.Contains(d, "/") {
			return "", nil, ErrAmbiguous
		}
		segs[i] = d
	}
	for _, op := range ops {
		if params, ok := op.match(method, segs); ok {
			return op.Name, params, nil
		}
	}
	return "", nil, nil
}

func (op Operation) match(method string, segs []string) (map[string]string, bool) {
	tmpl, _ := split(op.Path)
	if !strings.EqualFold(method, op.Method) || len(tmpl) != len(segs) {
		return nil, false
	}
	params := map[string]string{}
	for i, t := range tmpl {
		if p, ok := param(t); ok {
			params[p] = segs[i]
		} else if t != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// split returns the segments of an absolute path, refusing empty and dot
// segments. "/" has none.
func split(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	if path == "/" {
		return nil, true
	}
	segs := strings.Split(path[1:], "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return nil, false
		}
	}
	return segs, true
}

func param(seg string) (string, bool) {
	if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
		return seg[1 : len(seg)-1], true
	}
	return "", false
}

func host(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		target = h
	}
	return strings.TrimSuffix(strings.ToLower(target), ".")
}
