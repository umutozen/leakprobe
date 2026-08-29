package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

//go:embed default_rules.json
var embeddedRules []byte

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

var severityOrder = map[string]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

type Rule struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Patterns    []string `json:"patterns"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	compiled    []*regexp.Regexp
}

type RuleSet struct {
	Rules []Rule `json:"rules"`
}

func parseRuleSet(data []byte) (*RuleSet, error) {
	var set RuleSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	for i := range set.Rules {
		r := &set.Rules[i]
		if _, ok := severityOrder[r.Severity]; !ok {
			return nil, fmt.Errorf("invalid severity '%s' (rule: %s)", r.Severity, r.ID)
		}
		if r.Type == "content" {
			for _, p := range r.Patterns {
				re, err := regexp.Compile("(?i)" + p)
				if err != nil {
					return nil, fmt.Errorf("invalid regex (rule: %s): %w", r.ID, err)
				}
				r.compiled = append(r.compiled, re)
			}
		} else {
			for j := range r.Patterns {
				r.Patterns[j] = strings.ToLower(r.Patterns[j])
			}
		}
	}
	return &set, nil
}

func loadRules(extraRulesPath string) (*RuleSet, error) {
	set, err := parseRuleSet(embeddedRules)
	if err != nil {
		return nil, fmt.Errorf("embedded rules are broken: %w", err)
	}
	if extraRulesPath == "" {
		return set, nil
	}
	data, err := os.ReadFile(extraRulesPath)
	if err != nil {
		return nil, err
	}
	extraSet, err := parseRuleSet(data)
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	for i, r := range set.Rules {
		index[r.ID] = i
	}
	for _, r := range extraSet.Rules {
		if i, ok := index[r.ID]; ok {
			set.Rules[i] = r
		} else {
			set.Rules = append(set.Rules, r)
		}
	}
	return set, nil
}
