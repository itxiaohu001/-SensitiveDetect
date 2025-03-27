package SensitiveDetect

import (
	"path/filepath"
	"testing"
)

func TestLoadRulesFromYAML(t *testing.T) {
	yamlPath := filepath.Join("rules.yaml")
	err := LoadRulesFromFile(yamlPath)
	if err != nil {
		t.Fatalf("Failed to load rules from YAML: %v", err)
	}

	rules := DefaultRules()
	if len(rules) != 7 {
		t.Errorf("Expected 7 rules, got %d", len(rules))
	}

	// Test specific rules
	for _, rule := range rules {
		switch rule.ID {
		case "CN_ID_CARD":
			if !rule.Pattern.MatchString("110101199001011234") {
				t.Error("CN_ID_CARD pattern failed to match valid ID")
			}
		case "PASSWORD":
			if len(rule.Keywords) != 4 {
				t.Errorf("Expected 4 keywords for PASSWORD rule, got %d", len(rule.Keywords))
			}
		}
	}
}

func TestInvalidRuleFile(t *testing.T) {
	// Test non-existent file
	err := LoadRulesFromFile("non_existent.yaml")
	if err == nil {
		t.Error("Expected error when loading non-existent file")
	}
}
