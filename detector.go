package censorgo

import (
	"fmt"
	"io"
	"regexp"
	"sync"
)

// Rule represents a single detection rule
type Rule struct {
	ID          string         // Unique identifier for the rule
	Name        string         // Human readable name
	Description string         // Rule description
	Pattern     *regexp.Regexp // Compiled regular expression pattern
	Keywords    []string       // List of keywords to match
}

// Config holds configuration options for the detector
type Config struct {
	Rules       []Rule // List of detection rules
	Concurrency int    // Number of concurrent workers for processing
	StrictMode  bool   // If true, returns error on any rule match
}

// DefaultConfig returns a Config with sensible default values
func DefaultConfig() *Config {
	return &Config{
		Concurrency: 4,
		StrictMode:  false,
	}
}

// Detector represents the sensitive information detector
type Detector struct {
	config *Config
	mu     sync.RWMutex
}

// Match represents a detected sensitive information match
type Match struct {
	Rule     Rule   // The rule that triggered the match
	Content  string // The matched content
	Position int    // Position in the input where match was found
}

// Various error types that may be returned
var (
	ErrInvalidPattern  = fmt.Errorf("invalid pattern")
	ErrInvalidInput    = fmt.Errorf("invalid input")
	ErrInputTooLarge   = fmt.Errorf("input exceeds maximum size")
	ErrRuleNotFound    = fmt.Errorf("rule not found")
	ErrDetectionFailed = fmt.Errorf("detection failed")
)

// NewDetector creates a new Detector with the given configuration
func NewDetector(config *Config) (*Detector, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate configuration
	if config.Concurrency < 1 {
		config.Concurrency = 1
	}

	return &Detector{
		config: config,
	}, nil
}

// AddRule adds a new detection rule to the detector
func (d *Detector) AddRule(rule Rule) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if rule.Pattern == nil && len(rule.Keywords) == 0 {
		return ErrInvalidPattern
	}

	d.config.Rules = append(d.config.Rules, rule)
	return nil
}

// DetectString checks the input string for sensitive information
func (d *Detector) DetectString(input string) ([]Match, error) {
	var matches []Match
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Process each rule
	for _, rule := range d.config.Rules {
		// Check regular expression pattern
		if rule.Pattern != nil {
			for _, match := range rule.Pattern.FindAllStringIndex(input, -1) {
				matches = append(matches, Match{
					Rule:     rule,
					Content:  input[match[0]:match[1]],
					Position: match[0],
				})
			}
		}

		// Check keywords
		for _, keyword := range rule.Keywords {
			if idx := indexOf(input, keyword); idx >= 0 {
				matches = append(matches, Match{
					Rule:     rule,
					Content:  keyword,
					Position: idx,
				})
			}
		}
	}

	if len(matches) > 0 && d.config.StrictMode {
		return matches, ErrDetectionFailed
	}

	return matches, nil
}

// ScanReader processes an io.Reader in chunks for sensitive information
func (d *Detector) ScanReader(reader io.Reader) ([]Match, error) {
	var matches []Match
	buffer := make([]byte, 32*1024) // 32KB chunks

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			chunkMatches, err := d.DetectString(string(buffer[:n]))
			if err != nil && err != ErrDetectionFailed {
				return nil, err
			}
			matches = append(matches, chunkMatches...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	return matches, nil
}

// Helper function to find index of a substring
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
