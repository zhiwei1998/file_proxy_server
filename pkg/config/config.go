package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 常量定义
const (
	alistAPIURL  = "http://10.10.2.140:5244"
	alistToken   = "alist-xxxxxxxxxxxxxxxxxxxxxxx"
	testURL      = "https://www.baidu.com"
	defaultDNS   = "223.5.5.5:53"
	proxyTimeout = 600 * time.Second
)

// 日志级别常量
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// Config 应用配置结构体
type Config struct {
	Host             string `yaml:"host"`
	Port             int    `yaml:"port"`
	SocksHost        string `yaml:"socks_host"`
	SocksPort        int    `yaml:"socks_port"`
	SocksUsername    string `yaml:"socks_username"`
	SocksPassword    string `yaml:"socks_password"`
	LogLevel         string `yaml:"log_level"`
	AlistAPIURL      string `yaml:"alist_api_url"`
	AlistToken       string `yaml:"alist_token"`
	TestURL          string `yaml:"test_url"`
	DefaultDNS       string `yaml:"default_dns"`
	ProxyTimeout     int    `yaml:"proxy_timeout_seconds"`
	EnableRedirect   bool   `yaml:"enable_redirect"`   // 是否启用302跳转
	EnableCache      int    `yaml:"enable_cache"`      // 缓存配置，0表示禁用，其他数字表示缓存分钟数
	InterceptKeyword string `yaml:"intercept_keyword"` // 用于拦截重定向的关键词，支持多个关键词以|分隔，为空时关闭拦截功能
}

// SocksProxyConfig SOCKS代理配置结构体
type SocksProxyConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Enabled  bool
}

// Arguments 命令行参数结构体
type Arguments struct {
	Host           string
	Port           int
	SocksHost      string
	SocksPort      int
	SocksUsername  string
	SocksPassword  string
	LogLevel       string
	ConfigPath     string
	GenerateConfig bool
}

// AppConfig 全局应用配置
var AppConfig Config

// InitConfig 初始化默认配置
func InitConfig() {
	AppConfig = Config{
		Host:             "0.0.0.0",
		Port:             8001,
		LogLevel:         LogLevelInfo,
		AlistAPIURL:      alistAPIURL,
		AlistToken:       alistToken,
		TestURL:          testURL,
		DefaultDNS:       defaultDNS,
		ProxyTimeout:     int(proxyTimeout.Seconds()),
		EnableRedirect:   true, // 默认启用302跳转
		EnableCache:      5,    // 默认缓存5分钟
		InterceptKeyword: "",   // 默认关闭拦截功能，支持多个关键词以|分隔
	}
}

// LoadConfig 从文件加载配置
func LoadConfig(configPath string, args *Arguments) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	var fileConfig Config
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 更新应用配置（这些配置没有对应的命令行参数）
	if fileConfig.AlistAPIURL != "" {
		AppConfig.AlistAPIURL = fileConfig.AlistAPIURL
	}
	if fileConfig.AlistToken != "" {
		AppConfig.AlistToken = fileConfig.AlistToken
	}
	if fileConfig.TestURL != "" {
		AppConfig.TestURL = fileConfig.TestURL
	}
	if fileConfig.DefaultDNS != "" {
		AppConfig.DefaultDNS = fileConfig.DefaultDNS
	}
	if fileConfig.ProxyTimeout > 0 {
		AppConfig.ProxyTimeout = fileConfig.ProxyTimeout
	}
	// 更新302跳转、缓存和拦截关键词配置
	AppConfig.EnableRedirect = fileConfig.EnableRedirect
	AppConfig.EnableCache = fileConfig.EnableCache
	AppConfig.InterceptKeyword = fileConfig.InterceptKeyword

	// 更新命令行参数（仅当命令行参数为默认值时）
	if args.Host == "0.0.0.0" {
		args.Host = fileConfig.Host
	}
	if args.Port == 8001 {
		args.Port = fileConfig.Port
	}
	if args.SocksHost == "" {
		args.SocksHost = fileConfig.SocksHost
	}
	if args.SocksPort == 0 {
		args.SocksPort = fileConfig.SocksPort
	}
	// 只有当配置文件中的用户名和密码不为空时才更新
	if fileConfig.SocksUsername != "" {
		args.SocksUsername = fileConfig.SocksUsername
	}
	if fileConfig.SocksPassword != "" {
		args.SocksPassword = fileConfig.SocksPassword
	}
	if args.LogLevel == LogLevelInfo {
		args.LogLevel = fileConfig.LogLevel
	}

	return nil
}

// GenerateConfigFile 生成配置文件
func GenerateConfigFile(configPath string) error {
	// 如果文件已存在，询问是否覆盖
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("配置文件 %s 已存在，是否覆盖？(y/n): ", configPath)
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) != "y" {
			return fmt.Errorf("用户取消操作")
		}
	}

	// 创建带注释的配置内容，而不是直接使用结构体序列化
	configContent := `# 文件代理服务器配置文件
# 配置说明：
# 1. 服务器配置 - 控制服务监听地址和端口
# 2. SOCKS5代理配置 - 可选，用于代理请求
# 3. 日志配置 - 控制日志输出级别
# 4. Alist配置 - 用于处理Alist文件代理
# 5. 网络配置 - 控制DNS和超时设置
# 6. 功能配置 - 控制重定向、缓存和拦截功能

# ========== 服务器配置 ==========
# 监听主机地址，0.0.0.0表示监听所有网络接口
host: "0.0.0.0"
# 监听端口
port: 8001

# ========== SOCKS5代理配置 ==========
# SOCKS5代理服务器地址，留空表示不使用代理
socks_host: "127.0.0.1"
# SOCKS5代理服务器端口
socks_port: 1080
# SOCKS5代理用户名，可选
socks_username: "username"
# SOCKS5代理密码，可选
socks_password: "password"

# ========== 日志配置 ==========
# 日志级别：debug|info|warn|error，默认info
log_level: "info"

# ========== Alist配置 ==========
# Alist API地址，用于处理Alist文件代理
alist_api_url: "http://10.10.2.140:5244"
# Alist访问令牌，用于认证
alist_token: "alist-xxxxxxxxxxxxxxxxxxxxxxx"

# ========== 网络配置 ==========
# 测试URL，用于验证网络连接
test_url: "https://www.baidu.com"
# 默认DNS服务器，格式为host:port
default_dns: "223.5.5.5:53"
# 代理超时时间，单位为秒
proxy_timeout_seconds: 600

# ========== 功能配置 ==========
# 是否启用302跳转，true表示启用，false表示禁用
enable_redirect: true
# 缓存配置，0表示禁用，5表示缓存5分钟，10表示缓存10分钟
enable_cache: 5
# 重定向拦截关键词，支持多个关键词以|分隔，为空时关闭拦截功能
# 示例: 'app-free-download|app-download'
intercept_keyword: ""
`

	// 写入文件
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

// ParseArguments 解析命令行参数
func ParseArguments() (Arguments, error) {
	args := Arguments{
		Host:     "0.0.0.0",
		Port:     8001,
		LogLevel: LogLevelInfo,
		// 移除默认的 ConfigPath 设置
	}

	showHelp := false

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "--host":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少主机参数值")
			}
			args.Host = os.Args[i]
		case "--port":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少端口参数值")
			}
			port, err := strconv.Atoi(os.Args[i])
			if err != nil {
				return args, fmt.Errorf("无效的端口号: %v", err)
			}
			args.Port = port
		case "--socks-host":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少SOCKS主机参数值")
			}
			args.SocksHost = os.Args[i]
		case "--socks-port":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少SOCKS端口参数值")
			}
			port, err := strconv.Atoi(os.Args[i])
			if err != nil {
				return args, fmt.Errorf("无效的SOCKS端口号: %v", err)
			}
			args.SocksPort = port
		case "--socks-username":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少SOCKS用户名参数值")
			}
			args.SocksUsername = os.Args[i]
		case "--socks-password":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少SOCKS密码参数值")
			}
			args.SocksPassword = os.Args[i]
		case "--log-level":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少日志级别参数值")
			}
			level := strings.ToLower(os.Args[i])
			if level != LogLevelDebug && level != LogLevelInfo && level != LogLevelWarn && level != LogLevelError {
				return args, fmt.Errorf("无效的日志级别: %s", level)
			}
			args.LogLevel = level
		case "--config":
			i++
			if i >= len(os.Args) {
				return args, errors.New("缺少配置文件路径参数值")
			}
			args.ConfigPath = os.Args[i]
		case "--config-generate":
			args.GenerateConfig = true
			// 如果同时指定了生成配置但没有指定路径，使用默认路径
			if args.ConfigPath == "" {
				args.ConfigPath = "config.yaml"
			}
		case "--help", "-h":
			showHelp = true
		default:
			return args, fmt.Errorf("未知参数: %s", arg)
		}
	}

	if showHelp {
		PrintHelp()
		os.Exit(0)
	}

	return args, nil
}

// PrintHelp 打印帮助信息
func PrintHelp() {
	helpText := `文件代理服务器 - 支持SOCKS5代理

用法:
  file-proxy-server [参数]

参数:
  --host string         监听主机 (默认 "0.0.0.0")
  --port int            监听端口 (默认 8001)
  --socks-host string   SOCKS5代理地址
  --socks-port int      SOCKS5代理端口
  --socks-username string SOCKS5代理用户名
  --socks-password string SOCKS5代理密码
  --log-level string    日志级别 (debug|info|warn|error, 默认 "info")
  --config string       配置文件路径 (默认 "config.yaml")
  --config-generate     生成配置文件并退出
  --help, -h            显示帮助信息

示例:
  file-proxy-server --host 0.0.0.0 --port 8080
  file-proxy-server --socks-host 127.0.0.1 --socks-port 1080 --log-level debug
  file-proxy-server --config /path/to/config.yaml
  file-proxy-server --config-generate --config custom-config.yaml
`
	fmt.Println(helpText)
}