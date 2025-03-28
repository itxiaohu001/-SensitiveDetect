# censorgo

一个高性能的敏感信息检测库，支持自定义规则和并发处理。

## 功能特点

- 内置多种常见敏感信息检测规则（身份证、手机号、银行卡等）
- 支持正则表达式和关键词匹配
- 可通过YAML文件配置自定义规则
- 支持并发处理大文本
- 可自定义日志实现
- 支持严格模式和宽松模式

## 快速开始

### 基本用法

```go
func main() {
    // 使用默认配置创建检测器
    detector, err := censorgo.NewDetector(nil)
    if err != nil {
        panic(err)
    }

    // 检测文本中的敏感信息
    text := "我的手机号是13812345678，邮箱是example@email.com"
    matches, err := detector.DetectString(text)
    if err != nil {
        panic(err)
    }

    // 输出检测结果
    for _, match := range matches {
        fmt.Printf("发现敏感信息：%s (规则：%s)\n", match.Content, match.Rule.Name)
    }
}
```

### 自定义配置

```go
config := &censorgo.Config{
    Concurrency: 8,           // 设置并发数
    MaxTextSize: 2 * 1024 * 1024, // 设置最大文本大小为2MB
    StrictMode: true,         // 启用严格模式
}

detector, err := SensitiveDetect.NewDetector(config)
```

## 规则配置

### YAML规则文件

可以通过YAML文件配置检测规则：

```yaml
rules:
  - id: "CUSTOM_RULE"
    name: "自定义规则"
    description: "检测自定义模式"
    pattern: "\\b\\w+@example\\.com\\b"  # 正则表达式规则

  - id: "KEYWORD_RULE"
    name: "关键词规则"
    description: "检测特定关键词"
    keywords:  # 关键词列表
      - "secret"
      - "private"
```

### 加载规则文件

```go
err := censorgo.LoadRulesFromFile("rules.yaml")
if err != nil {
    panic(err)
}
```

## API文档

### 主要类型

- `Detector`: 敏感信息检测器
- `Config`: 检测器配置
- `Rule`: 检测规则
- `Match`: 匹配结果

### 核心方法

- `NewDetector(config *Config) (*Detector, error)`: 创建新的检测器
- `DetectString(input string) ([]Match, error)`: 检测字符串中的敏感信息
- `ScanReader(reader io.Reader) ([]Match, error)`: 从Reader中检测敏感信息
- `AddRule(rule Rule) error`: 添加新的检测规则
- `LoadRulesFromFile(filePath string) error`: 从YAML文件加载规则

### 内置规则

- 中国身份证号码
- 中国手机号码
- 银行卡号
- 电子邮件地址
- IPv4地址
- 密码相关关键词
- API密钥和令牌

## 错误处理

库定义了以下错误类型：

- `ErrInvalidPattern`: 无效的正则表达式模式
- `ErrInvalidInput`: 无效的输入
- `ErrInputTooLarge`: 输入超过最大大小限制
- `ErrRuleNotFound`: 规则未找到
- `ErrDetectionFailed`: 检测失败（严格模式下发现敏感信息）

## 性能优化

- 使用并发处理提高大文本处理速度
- 支持流式处理大文件
- 正则表达式预编译
- 高效的关键词匹配算法