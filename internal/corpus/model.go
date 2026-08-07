// Package corpus provides deterministic rule-corpus validation for GoBan.
// It is deliberately separate from the daemon runtime: the same matcher,
// timestamp, allowlist, tracker, and banner pipeline is exercised without
// adding any production attack surface.
package corpus

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

type Manifest struct {
	Version int              `yaml:"version" json:"version"`
	Sources []ExternalSource `yaml:"sources,omitempty" json:"sources,omitempty"`
	Cases   []Case           `yaml:"cases" json:"cases"`
}

type ExternalSource struct {
	ID             string `yaml:"id" json:"id"`
	Project        string `yaml:"project" json:"project"`
	URL            string `yaml:"url" json:"url"`
	License        string `yaml:"license" json:"license"`
	LicenseURL     string `yaml:"license_url,omitempty" json:"license_url,omitempty"`
	Redistribution string `yaml:"redistribution" json:"redistribution"`
	Adapter        string `yaml:"adapter" json:"adapter"`
	Rule           string `yaml:"rule,omitempty" json:"rule,omitempty"`
	FileName       string `yaml:"file_name" json:"file_name"`
	MaxBytes       int64  `yaml:"max_bytes,omitempty" json:"max_bytes,omitempty"`
	Notes          string `yaml:"notes,omitempty" json:"notes,omitempty"`
}

type Case struct {
	ID            string   `yaml:"id" json:"id"`
	Service       string   `yaml:"service" json:"service"`
	Rule          string   `yaml:"rule" json:"rule"`
	Format        string   `yaml:"format,omitempty" json:"format,omitempty"`
	Reference     string   `yaml:"reference,omitempty" json:"reference,omitempty"`
	Tags          []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Lines         []string `yaml:"lines" json:"lines"`
	Repeat        int      `yaml:"repeat,omitempty" json:"repeat,omitempty"`
	ExpectedIP    string   `yaml:"expected_ip,omitempty" json:"expected_ip,omitempty"`
	ExpectedMatch int      `yaml:"expected_matches" json:"expected_matches"`
	ExpectedBans  int      `yaml:"expected_bans" json:"expected_bans"`
}

func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus manifest %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("parse corpus manifest %s: %w", path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse corpus manifest %s: multiple YAML documents are not supported", path)
		}
		return nil, fmt.Errorf("parse corpus manifest %s: %w", path, err)
	}
	if err := manifest.Validate(); err != nil {
		return nil, fmt.Errorf("validate corpus manifest %s: %w", path, err)
	}
	return &manifest, nil
}

func (m *Manifest) Validate() error {
	if m.Version != CurrentVersion {
		return fmt.Errorf("version %d is unsupported; want %d", m.Version, CurrentVersion)
	}
	sourceIDs := make(map[string]struct{}, len(m.Sources))
	fileNames := make(map[string]struct{}, len(m.Sources))
	for i, src := range m.Sources {
		if err := validateIdentifier(src.ID); err != nil {
			return fmt.Errorf("sources[%d].id: %w", i, err)
		}
		if _, exists := sourceIDs[src.ID]; exists {
			return fmt.Errorf("sources[%d].id %q is duplicated", i, src.ID)
		}
		sourceIDs[src.ID] = struct{}{}
		if src.Project == "" || src.URL == "" || src.License == "" || src.Redistribution == "" || src.Adapter == "" || src.FileName == "" {
			return fmt.Errorf("sources[%d] %q: project, url, license, redistribution, adapter, and file_name are required", i, src.ID)
		}
		parsedURL, err := url.Parse(src.URL)
		if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
			return fmt.Errorf("sources[%d] %q: url must be an absolute HTTPS URL", i, src.ID)
		}
		if filepath.Base(src.FileName) != src.FileName || src.FileName == "." {
			return fmt.Errorf("sources[%d] %q: file_name must be a safe base name", i, src.ID)
		}
		if _, exists := fileNames[src.FileName]; exists {
			return fmt.Errorf("sources[%d] %q: file_name %q is duplicated", i, src.ID, src.FileName)
		}
		fileNames[src.FileName] = struct{}{}
		if src.Adapter != "fail2ban-annotated" && src.Adapter != "plain-scan" {
			return fmt.Errorf("sources[%d] %q: adapter %q is unsupported", i, src.ID, src.Adapter)
		}
		if src.Redistribution != "external-only" {
			return fmt.Errorf("sources[%d] %q: only external-only corpora are accepted", i, src.ID)
		}
		if src.MaxBytes < 0 {
			return fmt.Errorf("sources[%d] %q: max_bytes must be non-negative", i, src.ID)
		}
	}

	caseIDs := make(map[string]struct{}, len(m.Cases))
	for i, tc := range m.Cases {
		if err := validateIdentifier(tc.ID); err != nil {
			return fmt.Errorf("cases[%d].id: %w", i, err)
		}
		if _, exists := caseIDs[tc.ID]; exists {
			return fmt.Errorf("cases[%d].id %q is duplicated", i, tc.ID)
		}
		caseIDs[tc.ID] = struct{}{}
		if tc.Service == "" || tc.Rule == "" {
			return fmt.Errorf("cases[%d] %q: service and rule are required", i, tc.ID)
		}
		if len(tc.Lines) == 0 {
			return fmt.Errorf("cases[%d] %q: at least one line is required", i, tc.ID)
		}
		if tc.Repeat < 0 {
			return fmt.Errorf("cases[%d] %q: repeat must be non-negative", i, tc.ID)
		}
		if tc.ExpectedMatch < 0 || tc.ExpectedBans < 0 {
			return fmt.Errorf("cases[%d] %q: expected counts must be non-negative", i, tc.ID)
		}
		seenTags := make(map[string]struct{}, len(tc.Tags))
		for _, tag := range tc.Tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				return fmt.Errorf("cases[%d] %q: tags must not be empty", i, tc.ID)
			}
			if _, exists := seenTags[tag]; exists {
				return fmt.Errorf("cases[%d] %q: duplicate tag %q", i, tc.ID, tag)
			}
			seenTags[tag] = struct{}{}
		}
	}
	return nil
}

func validateIdentifier(value string) error {
	if value == "" {
		return fmt.Errorf("must not be empty")
	}
	if len(value) > 128 {
		return fmt.Errorf("%q exceeds 128 bytes", value)
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return fmt.Errorf("%q contains unsupported character %q", value, r)
	}
	return nil
}

func (m *Manifest) Filter(ruleName, service, tag string) []Case {
	out := make([]Case, 0, len(m.Cases))
	for _, tc := range m.Cases {
		if ruleName != "" && tc.Rule != ruleName {
			continue
		}
		if service != "" && tc.Service != service {
			continue
		}
		if tag != "" && !contains(tc.Tags, tag) {
			continue
		}
		out = append(out, tc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
