package config

import (
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
//	- name: sshd
//	  source: auth-log
//	  regex: 'Failed password for (?:invalid user )?\S+ from (?P<ip>\S+)'
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
	var bare []RuleConfig
	if err := yaml.Unmarshal(data, &bare); err == nil && len(bare) > 0 && bare[0].Name != "" {
		return bare, nil
	}
	var wrapper struct {
		Rules []RuleConfig `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return wrapper.Rules, nil
}
