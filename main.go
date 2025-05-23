package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

const (
	sizeLimit    = 1024 * 1024 * 1024 * 999
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

var (
	expFileURL = regexp.MustCompile(`^(https?://)([^/]+)(/.*)?$`)
	logLevel   = LogLevelInfo // 默认日志级别
)

type Config struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	SocksHost     string `yaml:"socks_host"`
	SocksPort     int    `yaml:"socks_port"`
	SocksUsername string `yaml:"socks_username"`
	SocksPassword string `yaml:"socks_password"`
	LogLevel      string `yaml:"log_level"`
	AlistAPIURL   string `yaml:"alist_api_url"`
	AlistToken    string `yaml:"alist_token"`
	TestURL       string `yaml:"test_url"`
	DefaultDNS    string `yaml:"default_dns"`
	ProxyTimeout  int    `yaml:"proxy_timeout_seconds"`
}

type SocksProxyConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Enabled  bool
}

type AlistResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"message"`
	Data struct {
		URL string `json:"url"`
	} `json:"data"`
}

type Arguments struct {
	Host          string
	Port          int
	SocksHost     string
	SocksPort     int
	SocksUsername string
	SocksPassword string
	LogLevel      string
	ConfigPath    string
	GenerateConfig bool
}

type flushWriter struct {
	w http.ResponseWriter
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

var (
	globalSocksProxy *SocksProxyConfig
	appConfig       Config
)

// 初始化配置
func init() {
	// 设置默认配置
	appConfig = Config{
		Host:         "0.0.0.0",
		Port:         8001,
		LogLevel:     LogLevelInfo,
		AlistAPIURL:  alistAPIURL,
		AlistToken:   alistToken,
		TestURL:      testURL,
		DefaultDNS:   defaultDNS,
		ProxyTimeout: int(proxyTimeout.Seconds()),
	}
}

// 日志函数
func logDebug(format string, v ...interface{}) {
	if logLevel == LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func logInfo(format string, v ...interface{}) {
	if logLevel == LogLevelDebug || logLevel == LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func logWarn(format string, v ...interface{}) {
	if logLevel == LogLevelDebug || logLevel == LogLevelInfo || logLevel == LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

func logError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}


func main() {
    args, err := parseArguments()
    if err != nil {
        logError("参数解析错误: %v\n使用 --help 查看帮助", err)
        os.Exit(1)
    }

    if args.GenerateConfig {
        if err := generateConfigFile(args.ConfigPath); err != nil {
            logError("生成配置文件失败: %v", err)
            os.Exit(1)
        }
        logInfo("配置文件已生成: %s", args.ConfigPath)
        os.Exit(0)
    }

    // 设置默认值（确保所有字段都有值）
    if args.Host == "" {
        args.Host = "0.0.0.0"
    }
    if args.Port == 0 {
        args.Port = 8001
    }
    if args.LogLevel == "" {
        args.LogLevel = LogLevelInfo
    }

    // 加载配置文件（如果有）
    if args.ConfigPath != "" {
        if err := loadConfig(args.ConfigPath, &args); err != nil {
            logError("加载配置文件失败: %v", err)
            os.Exit(1)
        }
        logInfo("成功加载配置文件: %s", args.ConfigPath)
    } else {
        logDebug("未指定配置文件，使用默认配置")
    }

    // 应用最终配置
    logLevel = args.LogLevel
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    logInfo("===== 启动服务 =====")
    logDebug("命令行参数: %+v", args)
    logDebug("应用配置: %+v", appConfig)

    // SOCKS代理配置
    if args.SocksHost != "" && args.SocksPort > 0 {
        globalSocksProxy = &SocksProxyConfig{
            Host:     args.SocksHost,
            Port:     args.SocksPort,
            Username: args.SocksUsername,
            Password: args.SocksPassword,
            Enabled:  true,
        }

        logInfo("全局SOCKS代理配置: %+v", globalSocksProxy)

        if !testProxyConnectivity(globalSocksProxy) {
            logWarn("代理测试失败，将禁用代理功能")
            globalSocksProxy.Enabled = false
        }
    }

    configureDNS(appConfig.DefaultDNS)

    r := mux.NewRouter()
    r.SkipClean(true)


    // 1. 首先处理带参数的URL（优先级最高）
    r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Query().Get("url") != "" && r.URL.Query().Get("path") != "" {
            handleURLWithParams(w, r)
            return
        }
        indexHandler(w, r) // 回退到默认处理
    })

    // 2. 其他路由处理
    r.PathPrefix("/").HandlerFunc(proxyHandler)

    

    server := &http.Server{
        Addr:         fmt.Sprintf("%s:%d", args.Host, args.Port),
        Handler:      r,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 0,
        IdleTimeout:  60 * time.Second,
    }

    logInfo("启动服务，监听 %s:%d", args.Host, args.Port)
    if err := server.ListenAndServe(); err != nil {
        logError("服务器启动失败: %v", err)
    }
}

// 加载配置文件
func loadConfig(configPath string, args *Arguments) error {
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
        appConfig.AlistAPIURL = fileConfig.AlistAPIURL
    }
    if fileConfig.AlistToken != "" {
        appConfig.AlistToken = fileConfig.AlistToken
    }
    if fileConfig.TestURL != "" {
        appConfig.TestURL = fileConfig.TestURL
    }
    if fileConfig.DefaultDNS != "" {
        appConfig.DefaultDNS = fileConfig.DefaultDNS
    }
    if fileConfig.ProxyTimeout > 0 {
        appConfig.ProxyTimeout = fileConfig.ProxyTimeout
    }

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
    if args.SocksUsername == "" {
        args.SocksUsername = fileConfig.SocksUsername
    }
    if args.SocksPassword == "" {
        args.SocksPassword = fileConfig.SocksPassword
    }
    if args.LogLevel == LogLevelInfo {
        args.LogLevel = fileConfig.LogLevel
    }

    return nil
}

// 生成配置文件
func generateConfigFile(configPath string) error {
	// 如果文件已存在，询问是否覆盖
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("配置文件 %s 已存在，是否覆盖？(y/n): ", configPath)
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) != "y" {
			return fmt.Errorf("用户取消操作")
		}
	}

	// 创建完整配置示例
	exampleConfig := Config{
		Host:          "0.0.0.0",
		Port:          8001,
		SocksHost:     "127.0.0.1",
		SocksPort:     1080,
		SocksUsername: "username",
		SocksPassword: "password",
		LogLevel:      "info",
		AlistAPIURL:   alistAPIURL,
		AlistToken:    alistToken,
		TestURL:       testURL,
		DefaultDNS:    defaultDNS,
		ProxyTimeout:  int(proxyTimeout.Seconds()),
	}

	data, err := yaml.Marshal(exampleConfig)
	if err != nil {
		return fmt.Errorf("生成YAML失败: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

func parseArguments() (Arguments, error) {
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
		printHelp()
		os.Exit(0)
	}

	return args, nil
}


func printHelp() {
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

func configureDNS(dnsServer string) {
	logDebug("配置DNS服务器: %s", dnsServer)
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Duration(appConfig.ProxyTimeout) * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
}

func testProxyConnectivity(proxyConfig *SocksProxyConfig) bool {
	logDebug("开始测试代理连通性 -> %s:%d", proxyConfig.Host, proxyConfig.Port)

	auth := &proxy.Auth{
		User:     proxyConfig.Username,
		Password: proxyConfig.Password,
	}
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port), auth, proxy.Direct)
	if err != nil {
		logError("创建SOCKS5拨号器失败: %v", err)
		return false
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				logInfo("通过代理建立连接到: %s %s", network, addr)
				return dialer.Dial(network, addr)
			},
		},
		Timeout: time.Duration(appConfig.ProxyTimeout) * time.Second,
	}

	logDebug("发送测试请求到: %s", appConfig.TestURL)
	resp, err := httpClient.Get(appConfig.TestURL)
	if err != nil {
		logError("代理测试失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	logInfo("代理测试成功，状态码: %d", resp.StatusCode)
	return true
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	logDebug("处理根路径请求")
	w.Write([]byte("欢迎使用文件代理服务器！请提供有效的文件URL。"))
}

// 专门处理带url和path参数的请求
func handleURLWithParams(w http.ResponseWriter, r *http.Request) {
    logDebug("处理带参数的URL请求")
    
    urlParam := r.URL.Query().Get("url")
    pathParam := r.URL.Query().Get("path")
    scParam := r.URL.Query().Get("sc")

    // 清理path中的查询参数（不保留sign等参数）
    cleanPath := strings.Split(pathParam, "?")[0]
    
    // 只有当提供了sc参数且path匹配时才处理
    if scParam != "" {
        scParam = strings.Trim(scParam, "/")
        cleanPath = strings.Trim(cleanPath, "/")
        
        // 检查path是否以sc开头
        if strings.HasPrefix(cleanPath, scParam+"/") {
            // 匹配时才移除sc部分
            cleanPath = cleanPath[len(scParam)+1:]
        } else if cleanPath == scParam {
            // 完全匹配时path置空
            cleanPath = ""
        }
        // 不匹配时保持原样
    }
    
    // 构建目标URL（不保留任何原始查询参数）
    targetURL := strings.TrimRight(urlParam, "/")
    if cleanPath != "" {
        targetURL += "/" + cleanPath
    }
    
    logInfo("转换参数: url=%s, sc=%s, path=%s", urlParam, scParam, pathParam)
    logInfo("转换结果: %s", targetURL)
    http.Redirect(w, r, targetURL, http.StatusFound)
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
    logDebug("===== 开始处理新请求 =====")
    logDebug("原始请求方法: %s", r.Method)
    logInfo("原始请求URL: %s", r.URL.String())
    logDebug("原始请求头: %+v", r.Header)

    // 原有逻辑保持不变
    rawPath := r.URL.EscapedPath()
    logDebug("原始编码路径: %s", rawPath)
    
    rawPath = strings.TrimPrefix(rawPath, "/")
    logDebug("处理后路径: %s", rawPath)

    if hasSignParamStrict(r.URL.String()) {
        logDebug("检测到Alist签名参数")
        logDebug("原始查询参数: %s", r.URL.String())
        
        realURL, err := getRealURL(r.URL.String())
        if err != nil {
            logError("Alist签名验证失败: %v", err)
            http.Error(w, "Alist签名验证失败", http.StatusBadRequest)
            return
        }
        logInfo("从Alist获取到真实URL: %s", realURL)
        proxyRequest(realURL, w, r)
        return
    }

    var targetURL string

    if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
        targetURL = rawPath
        logDebug("路径已经是完整URL，直接使用: %s", targetURL)
    } else {
        targetURL = "https://" + rawPath
        logDebug("路径补全为HTTPS URL: %s", targetURL)
    }

    if strings.Contains(targetURL, ":///") {
        oldURL := targetURL
        targetURL = strings.Replace(targetURL, ":///", "://", 1)
        logDebug("修复多余斜杠: %s → %s", oldURL, targetURL)
    }

    if !expFileURL.MatchString(targetURL) {
        logError("URL格式验证失败: %s", targetURL)
        http.Error(w, "无效的URL格式", http.StatusBadRequest)
        return
    }
    logDebug("URL格式验证通过: %s", targetURL)

    logDebug("准备转发请求到目标URL: %s", targetURL)
    proxyRequest(targetURL, w, r)
}



func hasSignParamStrict(urlStr string) bool {
	logDebug("检查签名参数: %s", urlStr)
	u, err := url.Parse(urlStr)
	if err != nil {
		logError("URL解析失败: %v", err)
		return false
	}

	query := u.Query()
	result := query.Has("sign") && strings.HasPrefix(u.RawQuery, "sign=")
	logDebug("判断是否是ALIST链接结果: %v", result)
	return result
}

func generateSign(path, token string, expire int) string {
	logDebug("生成签名: path=%s, expire=%d", path, expire)
	toSign := fmt.Sprintf("%s:%d", path, expire)
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(toSign))
	digest := h.Sum(nil)
	sign := base64.URLEncoding.EncodeToString(digest)
	result := fmt.Sprintf("%s:%d", sign, expire)
	logDebug("生成的签名: %s", result)
	return result
}

func verifySign(path, fullSign, token string) bool {
	logDebug("验证签名: path=%s, fullSign=%s", path, fullSign)
	parts := strings.Split(fullSign, ":")
	if len(parts) != 2 {
		logError("签名格式无效，需要两部分，得到 %d 部分", len(parts))
		return false
	}

	receivedSign := parts[0]
	expireStr := parts[1]

	expire, err := strconv.Atoi(expireStr)
	if err != nil {
		logError("过期时间解析失败: %v", err)
		return false
	}

	expectedSign := generateSign(path, token, expire)
	expectedSignPart := strings.Split(expectedSign, ":")[0]

	result := hmac.Equal(
		[]byte(strings.TrimRight(receivedSign, "=")),
		[]byte(strings.TrimRight(expectedSignPart, "=")),
	)
	logInfo("验证sign结果: %v", result)
	return result
}

func getRealURL(proxyURL string) (string, error) {
	logDebug("开始解析Alist代理URL: %s", proxyURL)
	
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		logError("URL解析失败: %v", err)
		return "", fmt.Errorf("解析URL失败: %w", err)
	}

	decodedPath, err := url.PathUnescape(parsed.Path)
	if err != nil {
		logError("URL解码失败: %v", err)
		return "", fmt.Errorf("URL解码失败: %w", err)
	}

	sign := parsed.Query().Get("sign")
	if sign == "" {
		logError("缺少签名参数")
		return "", errors.New("缺少签名参数")
	}

	if !verifySign(decodedPath, sign, appConfig.AlistToken) {
		logError("签名验证失败")
		return "", errors.New("签名验证失败")
	}

	apiURL := appConfig.AlistAPIURL + "/api/fs/link"
	headers := map[string]string{
		"Authorization": appConfig.AlistToken,
		"Content-Type":  "application/json",
	}

	data := map[string]string{"path": decodedPath}
	jsonData, err := json.Marshal(data)
	if err != nil {
		logError("JSON编码失败: %v", err)
		return "", fmt.Errorf("JSON编码失败: %w", err)
	}

	logDebug("准备请求Alist API: %s", apiURL)
	logDebug("请求数据: %s", jsonData)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		logError("创建请求失败: %v", err)
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: time.Duration(appConfig.ProxyTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logError("请求Alist API失败: %v", err)
		return "", fmt.Errorf("请求Alist API失败: %w", err)
	}
	defer resp.Body.Close()

	logDebug("Alist API响应状态码: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		logError("Alist API返回非200状态码: %d", resp.StatusCode)
		return "", fmt.Errorf("Alist API返回非200状态码: %d", resp.StatusCode)
	}

	var alistResp AlistResponse
	if err := json.NewDecoder(resp.Body).Decode(&alistResp); err != nil {
		logError("解析Alist响应失败: %v", err)
		return "", fmt.Errorf("解析Alist响应失败: %w", err)
	}

	logDebug("Alist API响应: %+v", alistResp)

	if alistResp.Code != 200 {
		logError("Alist API返回错误: %s", alistResp.Msg)
		return "", fmt.Errorf("Alist API返回错误: %s", alistResp.Msg)
	}

	logDebug("获取到真实URL: %s", alistResp.Data.URL)
	return alistResp.Data.URL, nil
}

func proxyRequest(targetURL string, w http.ResponseWriter, r *http.Request) {
	logDebug("===== 开始代理请求 =====")
	logInfo("目标URL: %s", targetURL)
	logDebug("原始请求方法: %s", r.Method)

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logError("创建请求失败: %v", err)
		http.Error(w, fmt.Sprintf("创建请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	for k, v := range r.Header {
		req.Header[k] = v
		logDebug("复制请求头: %s = %v", k, v)
	}

	req.Header.Del("Connection")
	req.Header.Del("Accept-Encoding")

	var client *http.Client

	if globalSocksProxy != nil && globalSocksProxy.Enabled {
		logDebug("使用全局SOCKS代理转发请求")
		logDebug("代理配置: %+v", globalSocksProxy)

		auth := &proxy.Auth{
			User:     globalSocksProxy.Username,
			Password: globalSocksProxy.Password,
		}
		dialer, err := proxy.SOCKS5("tcp", 
			fmt.Sprintf("%s:%d", globalSocksProxy.Host, globalSocksProxy.Port), 
			auth, 
			proxy.Direct)
		if err != nil {
			logError("创建SOCKS5拨号器失败: %v", err)
			http.Error(w, fmt.Sprintf("代理设置失败: %v", err), http.StatusInternalServerError)
			return
		}

		client = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					logInfo("通过代理建立连接到: %s %s", network, addr)
					return dialer.Dial(network, addr)
				},
			},
			Timeout: time.Duration(appConfig.ProxyTimeout) * time.Second,
		}
	} else {
		logInfo("使用直连方式转发请求")
		client = &http.Client{
			Timeout: time.Duration(appConfig.ProxyTimeout) * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
	}

	logDebug("发送请求到目标服务器")
	resp, err := client.Do(req)
	if err != nil {
		logError("请求失败: %v", err)
		http.Error(w, fmt.Sprintf("请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	logDebug("收到响应，状态码: %d", resp.StatusCode)
	logDebug("响应头: %+v", resp.Header)

	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err == nil {
		logDebug("检测到内容长度: %d", contentLength)
		if contentLength > sizeLimit {
			logError("文件大小超出限制: %d", contentLength)
			http.Error(w, "文件过大，请手动下载。", http.StatusRequestEntityTooLarge)
			return
		}
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	logInfo("开始传输响应内容")

	buf := make([]byte, 32 * 1024)
	_, err = io.CopyBuffer(&flushWriter{w}, resp.Body, buf)
	if err != nil {
		if isClosedConnectionError(err) {
			logWarn("客户端断开连接: %v", err)
			return
		}
		logError("流式传输失败: %v", err)
		http.Error(w, "传输中断", http.StatusInternalServerError)
	} else {
		logDebug("响应内容传输完成")
	}
}

func isClosedConnectionError(err error) bool {
	result := errors.Is(err, net.ErrClosed) || 
		strings.Contains(err.Error(), "broken pipe") || 
		strings.Contains(err.Error(), "connection reset")
	if result {
		logDebug("检测到连接关闭错误: %v", err)
	}
	return result
}
