package censorgo

import (
	"strings"
	"testing"
)

func TestScanReader_LineNumbers(t *testing.T) {
	// 创建多行文本
	text := "line1\nline2\npassword\nline4\n"

	detector, err := NewDetector(DefaultConfig())
	if err != nil {
		t.Fatalf("Failed to create detector: %v", err)
	}

	// 添加测试规则
	err = detector.AddRule(Rule{
		ID:       "TEST_LINE",
		Keywords: []string{"password"},
	})
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// 执行扫描
	matches, err := detector.ScanReader(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ScanReader failed: %v", err)
	}

	// 验证行号是否正确
	if len(matches) != 1 {
		t.Fatalf("Expected 1 match, but got %d", len(matches))
	}
	if matches[0].Line != 3 {
		t.Errorf("Expected match on line 3, but got line %d", matches[0].Line)
	}
}
