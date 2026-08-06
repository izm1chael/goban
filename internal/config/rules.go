package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadRulesFile reads a YAML file that contains a top-level list of RuleConfig
// entries. Convenient for shipping per-application rule bundles (e.g.
// /etc/goban/rules.d/sshd.yaml).
//
// The expected YAML shape is either a bare list:
//
//   - name: sshd
//     source: auth-log
//     regex: 'Failed password for (?:invalid user )?\S+ from (?P<ip>\S+)'
//
// or a wrapper object with a top-level "rules:" key:
//
//	rules:
//	  - name: sshd
//	    ...
//
// Both forms are accepted to make hand-editing easier.
func LoadRulesFile(path string) ([]RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&node); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := requireYAMLEOF(dec); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(node.Content) == 0 {
		return nil, nil
	}
	root := node.Content[0]
	switch root.Kind {
	case yaml.SequenceNode:
		var rules []RuleConfig
		if err := root.Decode(&rules); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		// Decode again through a strict wrapper so unknown fields inside list
		// elements are rejected by KnownFields.
		strict := yaml.NewDecoder(bytes.NewReader(data))
		strict.KnownFields(true)
		if err := strict.Decode(&rules); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return rules, nil
	case yaml.MappingNode:
		var wrapper struct {
			Rules []RuleConfig `yaml:"rules"`
		}
		strict := yaml.NewDecoder(bytes.NewReader(data))
		strict.KnownFields(true)
		if err := strict.Decode(&wrapper); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return wrapper.Rules, nil
	default:
		return nil, fmt.Errorf("parse %s: expected a rule list or rules: mapping", path)
	}
}
