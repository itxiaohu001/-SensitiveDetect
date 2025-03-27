package SensitiveDetect

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// Mock logger for testing
type mockLogger struct{}

func (l *mockLogger) Debug(args ...interface{}) {}
func (l *mockLogger) Info(args ...interface{})  {}
func (l *mockLogger) Warn(args ...interface{})  {}
func (l *mockLogger) Error(args ...interface{}) {}

func TestNewDetector(t *testing.T) {
	// Test with nil config
	detector, err := NewDetector(nil)
	if err != nil {
		t.Errorf("NewDetector(nil) returned error: %v", err)
	}
	if detector.config.Concurrency != 4 {
		t.Errorf("Expected default concurrency 4, got %d", detector.config.Concurrency)
	}

	// Test with custom config
	custom := &Config{
		Concurrency: 2,
		MaxTextSize: 512,
		StrictMode:  true,
		Logger:      &mockLogger{},
	}
	detector, err = NewDetector(custom)
	if err != nil {
		t.Errorf("NewDetector(custom) returned error: %v", err)
	}
	if detector.config.Concurrency != 2 {
		t.Errorf("Expected concurrency 2, got %d", detector.config.Concurrency)
	}
}

func TestAddRule(t *testing.T) {
	detector, _ := NewDetector(nil)

	// Test adding valid rule
	rule := Rule{
		ID:          "TEST_RULE",
		Name:        "Test Rule",
		Description: "Test rule description",
		Pattern:     regexp.MustCompile(`test\d+`),
	}
	if err := detector.AddRule(rule); err != nil {
		t.Errorf("AddRule() returned error: %v", err)
	}

	// Test adding invalid rule
	invalidRule := Rule{
		ID:   "INVALID",
		Name: "Invalid Rule",
	}
	if err := detector.AddRule(invalidRule); err != ErrInvalidPattern {
		t.Errorf("Expected ErrInvalidPattern, got %v", err)
	}
}

func TestDetectString(t *testing.T) {
	detector, _ := NewDetector(&Config{
		Rules: DefaultRules(),
	})

	tests := []struct {
		name     string
		input    string
		expected int // expected number of matches
	}{
		{
			name:     "ID Card",
			input:    "身份证号码：330102199901011234",
			expected: 1,
		},
		{
			name:     "Phone Number",
			input:    "联系电话：13812345678",
			expected: 1,
		},
		{
			name:     "Multiple Matches",
			input:    "电话：13812345678，邮箱：test@example.com",
			expected: 2,
		},
		{
			name:     "No Match",
			input:    "普通文本内容",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := detector.DetectString(tt.input)
			if err != nil {
				t.Errorf("DetectString() returned error: %v", err)
			}
			if len(matches) != tt.expected {
				t.Errorf("Expected %d matches, got %d", tt.expected, len(matches))
			}
		})
	}

	// Test input size limit
	longInput := strings.Repeat("a", 2*1024*1024)
	_, err := detector.DetectString(longInput)
	if err != ErrInputTooLarge {
		t.Errorf("Expected ErrInputTooLarge, got %v", err)
	}
}

func TestScanReader(t *testing.T) {
	detector, _ := NewDetector(&Config{
		Rules: DefaultRules(),
	})

	// Test with small reader
	input := "手机：13812345678\n邮箱：test@example.com"
	reader := bytes.NewReader([]byte(input))

	matches, err := detector.ScanReader(reader)
	if err != nil {
		t.Errorf("ScanReader() returned error: %v", err)
	}
	if len(matches) != 2 {
		t.Errorf("Expected 2 matches, got %d", len(matches))
	}

	// Test with large reader (multiple chunks)
	longInput := strings.Repeat("手机：13812345678\n", 1000)
	reader = bytes.NewReader([]byte(longInput))

	matches, err = detector.ScanReader(reader)
	if err != nil {
		t.Errorf("ScanReader() returned error: %v", err)
	}
	if len(matches) != 1000 {
		t.Errorf("Expected 1000 matches, got %d", len(matches))
	}
}

func TestStrictMode(t *testing.T) {
	detector, _ := NewDetector(&Config{
		Rules:      DefaultRules(),
		StrictMode: true,
	})

	// Test with matching input in strict mode
	input := "手机号码：13812345678"
	matches, err := detector.DetectString(input)
	if err != ErrDetectionFailed {
		t.Errorf("Expected ErrDetectionFailed, got %v", err)
	}
	if len(matches) != 1 {
		t.Errorf("Expected 1 match, got %d", len(matches))
	}
}

func BenchmarkDetectString(b *testing.B) {
	detector, _ := NewDetector(&Config{
		Rules: DefaultRules(),
	})

	input := "这是一段测试文本，包含手机号13812345678和邮箱test@example.com，以及身份证号330102199901011234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = detector.DetectString(input)
	}
}

func BenchmarkScanReader(b *testing.B) {
	detector, _ := NewDetector(&Config{
		Rules: DefaultRules(),
	})

	input := strings.Repeat("手机：13812345678\n邮箱：test@example.com\n", 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader([]byte(input))
		_, _ = detector.ScanReader(reader)
	}
}
