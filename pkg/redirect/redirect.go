package redirect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"
)

// FollowRedirects 处理URL重定向
// initialURL: 初始URL地址
// cfg: 应用配置
// socksProxy: SOCKS代理配置（可为nil）
func FollowRedirects(initialURL string, cfg *config.Config, socksProxy *config.SocksProxyConfig) (string, error) {
	var interceptedURL string

	// 基本URL验证
	if !strings.HasPrefix(initialURL, "http://") && !strings.HasPrefix(initialURL, "https://") {
		logger.LogError("无效的URL，缺少HTTP/HTTPS协议前缀: %s", initialURL)
		return initialURL, fmt.Errorf("无效的URL格式: %s", initialURL)
	}

	logger.LogInfo("开始在服务器端处理重定向")
	logger.LogInfo("请求地址：%s", initialURL)
	// 设置超时时间，确保使用默认值即使配置未初始化
	timeout := 600 * time.Second
	if cfg.ProxyTimeout > 0 {
		timeout = time.Duration(cfg.ProxyTimeout) * time.Second
	}
	logger.LogDebug("使用超时设置: %v", timeout)

	// 创建自定义HTTP传输
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
		// 添加连接池配置
		MaxIdleConnsPerHost:   20,
		ExpectContinueTimeout: 1 * time.Second,
		// 更可靠的重定向处理配置
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
	}

	// 如果配置了SOCKS代理，使用代理
	if socksProxy != nil && socksProxy.Enabled {
		auth := &proxy.Auth{
			User:     socksProxy.Username,
			Password: socksProxy.Password,
		}
		dialer, err := proxy.SOCKS5("tcp",
			fmt.Sprintf("%s:%d", socksProxy.Host, socksProxy.Port),
			auth,
			proxy.Direct)
		if err != nil {
			logger.LogWarn("创建SOCKS5拨号器失败，将使用直接连接: %v", err)
			// 不返回错误，而是使用直接连接
		} else {
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				logger.LogDebug("通过代理建立连接到: %s %s", network, addr)
				return dialer.Dial(network, addr)
			}
		}
	}

	// 为302重定向操作专门设置10秒超时
	redirectTimeout := 10 * time.Second
	client := &http.Client{
		Transport: transport,
		Timeout:   redirectTimeout, // 使用固定的10秒超时用于重定向操作
		// 允许自动重定向，这样服务器端会自动处理所有跳转
		// 使用默认的CheckRedirect行为，但增加重定向次数限制
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 增加重定向次数限制到20次，确保捕获所有跳转
			if len(via) >= 10 {
				logger.LogWarn("达到最大重定向次数限制: %d", len(via))
				// 记录最后一次希望跳转的目标URL
				interceptedURL = req.URL.String()
				return http.ErrUseLastResponse
			}
			// 链接关键词检测 - 只有当配置了拦截关键词时才执行检测
			// 支持多个关键词以|分隔，匹配任意一个就算成功
			if cfg.InterceptKeyword != "" {
				urlString := req.URL.String()
				logger.LogDebug("正在检查重定向URL: %s 是否包含拦截关键词", urlString)
				keywords := strings.Split(cfg.InterceptKeyword, "|")
				logger.LogDebug("当前配置的拦截关键词列表: %v", keywords)
				for _, keyword := range keywords {
					// 去除关键词两端的空格
					keyword = strings.TrimSpace(keyword)
					logger.LogDebug("检查关键词: '%s'", keyword)
					if keyword != "" {
						containsKeyword := strings.Contains(urlString, keyword)
						logger.LogDebug("URL '%s' %s 包含关键词 '%s'", urlString, map[bool]string{true: "确实", false: "不"}[containsKeyword], keyword)
						if containsKeyword {
							logger.LogInfo("检测到重定向URL包含拦截关键词'%s'，结束重定向", keyword)
							// 记录最后一次希望跳转的目标URL
							interceptedURL = urlString
							return http.ErrUseLastResponse
						} else {
							logger.LogDebug("重定向URL不包含拦截关键词'%s'，继续检查下一个关键词", keyword)
						}
					}
				}
				logger.LogInfo("重定向URL不包含任何配置的拦截关键词，继续重定向")
			} else {
				logger.LogDebug("未配置拦截关键词，跳过关键词检测")
			}

			// 记录每次重定向的来源和目标，便于调试
			logger.LogDebug("服务器端自动处理重定向: %s -> %s", via[len(via)-1].URL, req.URL)

			// 允许重定向继续
			return nil
		},
	}

	// 创建一个GET请求，使用Range头部只获取第一个字节，减少带宽使用
	req, err := http.NewRequest("GET", initialURL, nil)
	if err != nil {
		logger.LogError("创建请求失败: %v", err)
		return "", err
	}

	// 设置更完整的头部信息，模拟真实浏览器行为，确保能正确处理所有重定向
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Range", "bytes=0-0") // 只获取文件的第一个字节，减少带宽使用

	// 添加重试逻辑，最多重试3次
	maxRetries := 3
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 重试前等待一段时间（指数退避）
			waitTime := time.Duration(attempt) * 500 * time.Millisecond
			logger.LogInfo("连接超时，正在进行第%d次重试，等待%dms...", attempt, waitTime/time.Millisecond)
			time.Sleep(waitTime)
		}

		// 创建带有上下文的请求，支持超时控制
		ctx, cancel := context.WithTimeout(context.Background(), redirectTimeout)
		defer cancel()
		reqWithContext := req.WithContext(ctx)

		logger.LogDebug("发送请求到: %s (尝试 %d/%d)", initialURL, attempt+1, maxRetries+1)
		resp, err = client.Do(reqWithContext)
		if err == nil {
			// 请求成功，跳出循环
			break
		}

		lastErr = err
		// 检查是否是连接超时错误或EOF错误
		var netErr net.Error
		isTimeout := errors.As(err, &netErr) && netErr.Timeout()
		isEOF := strings.Contains(err.Error(), "EOF")

		if isTimeout || isEOF {
			logger.LogWarn("遇到网络错误: %v，将重试", err)
			// 继续循环重试
		} else {
			// 非超时错误，不重试
			logger.LogError("非超时错误: %v，不重试", err)
			break
		}
	}

	if err != nil {
		logger.LogError("请求失败 (所有重试均失败): %v", lastErr)
		return "", lastErr
	}

	// 确保总是关闭响应体
	defer resp.Body.Close()

	// 读取少量响应体以确保连接被正确关闭
	io.ReadAll(resp.Body)

	// 获取最终URL
	finalURL := resp.Request.URL.String()

	// 因策略中断重定向，返回中断时记录的目标URL
	if interceptedURL != "" {
		finalURL = interceptedURL
	}

	// 检查是否发生了重定向
	if resp.Request.URL.String() != initialURL {
		logger.LogInfo("成功完成所有重定向，获取到最终URL")
		logger.LogDebug("初始URL: %s", initialURL)
		logger.LogDebug("最终URL: %s", finalURL)
	} else {
		logger.LogInfo("没有发生重定向，使用原始URL")
	}

	return finalURL, nil
}