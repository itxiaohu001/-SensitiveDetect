package censorgo

import (
	"fmt"
	"os"
	"regexp"
	"sync"

	"gopkg.in/yaml.v3"
)

// RuleConfig represents the structure of the rules configuration file
type RuleConfig struct {
	Rules []RuleDefinition `yaml:"rules"`
}

// RuleDefinition represents a single rule in the configuration
type RuleDefinition struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Pattern     string   `yaml:"pattern,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty"`
}

var (
	// rulesMutex protects concurrent access to the rules
	rulesMutex sync.RWMutex
	// loadedRules stores the currently loaded rules
	loadedRules []Rule
)

// LoadRulesFromFile loads rules from a YAML file
func LoadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	var config RuleConfig
	err = yaml.Unmarshal(data, &config)

	if err != nil {
		return fmt.Errorf("failed to parse rules file: %w", err)
	}

	// Convert config rules to Rule structs
	rules := make([]Rule, 0, len(config.Rules))
	for _, def := range config.Rules {
		rule := Rule{
			ID:          def.ID,
			Name:        def.Name,
			Description: def.Description,
			Keywords:    def.Keywords,
		}
		if def.Pattern != "" {
			pattern, err := regexp.Compile(def.Pattern)
			if err != nil {
				return fmt.Errorf("invalid pattern for rule %s: %w", def.ID, err)
			}
			rule.Pattern = pattern
		}
		rules = append(rules, rule)
	}

	// Update rules atomically
	rulesMutex.Lock()
	loadedRules = rules
	rulesMutex.Unlock()

	return nil
}

// DefaultRules returns a slice of commonly used detection rules
func DefaultRules() []Rule {
	rulesMutex.RLock()
	defer rulesMutex.RUnlock()

	// If rules have been loaded from file, return those
	if len(loadedRules) > 0 {
		return loadedRules
	}

	// Otherwise, return the built-in default rules
	return []Rule{
		{
			ID:          "CN_ID_CARD",
			Name:        "Chinese ID Card Number",
			Description: "Matches 18-digit Chinese Resident ID Card numbers",
			Pattern:     regexp.MustCompile(`[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]`),
		},
		{
			ID:          "CN_MOBILE",
			Name:        "Chinese Mobile Number",
			Description: "Matches Chinese mobile phone numbers",
			Pattern:     regexp.MustCompile(`1[3-9]\d{9}`),
		},
		{
			ID:          "BANK_CARD",
			Name:        "Bank Card Number",
			Description: "Matches 13-19 digit bank card numbers",
			Pattern:     regexp.MustCompile(`\b\d{13,19}\b`),
		},
		{
			ID:          "EMAIL",
			Name:        "Email Address",
			Description: "Matches email addresses",
			Pattern:     regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		},
		{
			ID:          "IPV4",
			Name:        "IPv4 Address",
			Description: "Matches IPv4 addresses",
			Pattern:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		},
		{
			ID:          "PASSWORD",
			Name:        "Password Related",
			Description: "Matches common password-related keywords",
			Keywords:    []string{"password", "密码", "pwd", "passwd"},
		},
		{
			ID:          "API_KEY",
			Name:        "API Keys and Tokens",
			Description: "Matches common API key and token patterns",
			Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret[_-]?key)[:=]\s*['"]([^'"]+)['"]`),
		},
	}
}
