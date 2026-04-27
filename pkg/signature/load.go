package signature

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadFS(fsys fs.FS, root string) ([]Signature, error) {
	var signatures []Signature
	err := fs.WalkDir(fsys, root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !isYAML(path) {
			return nil
		}

		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		sig, err := parse(data, path)
		if err != nil {
			return err
		}
		signatures = append(signatures, sig)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sortSignatures(signatures)
	return signatures, nil
}

func LoadPaths(paths []string) ([]Signature, error) {
	var signatures []Signature
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			if !isYAML(path) {
				continue
			}
			sig, err := loadFile(path)
			if err != nil {
				return nil, err
			}
			signatures = append(signatures, sig)
			continue
		}

		err = filepath.WalkDir(path, func(filePath string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !isYAML(filePath) {
				return nil
			}
			sig, err := loadFile(filePath)
			if err != nil {
				return err
			}
			signatures = append(signatures, sig)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sortSignatures(signatures)
	return signatures, nil
}

func Merge(base, overrides []Signature) []Signature {
	out := make([]Signature, 0, len(base)+len(overrides))
	index := make(map[string]int, len(base)+len(overrides))

	for _, sig := range base {
		index[sig.ID] = len(out)
		out = append(out, sig)
	}
	for _, sig := range overrides {
		if pos, ok := index[sig.ID]; ok {
			out[pos] = sig
			continue
		}
		index[sig.ID] = len(out)
		out = append(out, sig)
	}

	sortSignatures(out)
	return out
}

func loadFile(path string) (Signature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Signature{}, err
	}
	return parse(data, path)
}

func parse(data []byte, source string) (Signature, error) {
	var sig Signature
	if err := yaml.Unmarshal(data, &sig); err != nil {
		return Signature{}, fmt.Errorf("%s: %w", source, err)
	}
	sig.Source = source
	if err := sig.Validate(); err != nil {
		return Signature{}, fmt.Errorf("%s: %w", source, err)
	}
	return sig, nil
}

func isYAML(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func sortSignatures(signatures []Signature) {
	sort.Slice(signatures, func(i, j int) bool {
		return signatures[i].ID < signatures[j].ID
	})
}
