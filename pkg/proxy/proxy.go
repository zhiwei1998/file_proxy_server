package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"
	"file-proxy/pkg/alist"

	"golang.org/x/net/proxy"
)

const (
	SizeLimit = 1024 * 1024 * 1024 * 999
)

var (
	ExpFileURL = regexp.MustCompile(`^(https?://)([^/]+)(/.*)?$`)
)

// flushWriter 用于实现响应流的即时刷新
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

// ProxyHandler 主代理处理函数
func ProxyHandler(w http.ResponseWriter, r *http.Request, cfg *config.Config, socksProxy *config.SocksProxyConfig) {
	logger.LogDebug("===== 开始处理新请求 =====")
	logger.LogDebug("原始请求方法: %s", r.Method)
	logger.LogInfo("原始请求URL: %s", r.URL.String())
	logger.LogDebug("原始请求头: %+v", r.Header)

	// 原有逻辑保持不变
	rawPath := r.URL.EscapedPath()
	logger.LogDebug("原始编码路径: %s", rawPath)

	rawPath = strings.TrimPrefix(rawPath, "/")
	logger.LogDebug("处理后路径: %s", rawPath)

	if HasSignParamStrict(r.URL.String()) {
		logger.LogDebug("检测到Alist签名参数")
		logger.LogDebug("原始查询参数: %s", r.URL.String())

		realURL, err := alist.GetRealURL(r.URL.String(), cfg)
		if err != nil {
			logger.LogError("Alist签名验证失败: %v", err)
			http.Error(w, "Alist签名验证失败", http.StatusBadRequest)
			return
		}
		logger.LogInfo("从Openlist获取到真实URL: %s", realURL)
		ProxyRequest(realURL, w, r, socksProxy, time.Duration(cfg.ProxyTimeout)*time.Second, SizeLimit)
		return
	}

	var targetURL string

	if strings.HasPrefix(rawPath, "http://") || strings.HasPrefix(rawPath, "https://") {
		targetURL = rawPath
		logger.LogDebug("路径已经是完整URL，直接使用: %s", targetURL)
	} else {
		targetURL = "https://" + rawPath
		logger.LogDebug("路径补全为HTTPS URL: %s", targetURL)
	}

	if strings.Contains(targetURL, ":///") {
		oldURL := targetURL
		targetURL = strings.Replace(targetURL, ":///", "://", 1)
		logger.LogDebug("修复多余斜杠: %s → %s", oldURL, targetURL)
	}

	if !ExpFileURL.MatchString(targetURL) {
		logger.LogError("URL格式验证失败: %s", targetURL)
		http.Error(w, "无效的URL格式", http.StatusBadRequest)
		return
	}
	logger.LogDebug("URL格式验证通过: %s", targetURL)

	logger.LogDebug("准备转发请求到目标URL: %s", targetURL)
	ProxyRequest(targetURL, w, r, socksProxy, time.Duration(cfg.ProxyTimeout)*time.Second, SizeLimit)
}

// HasSignParamStrict 严格检查URL是否包含Alist签名参数
func HasSignParamStrict(urlStr string) bool {
	logger.LogDebug("检查签名参数: %s", urlStr)
	u, err := url.Parse(urlStr)
	if err != nil {
		logger.LogError("URL解析失败: %v", err)
		return false
	}

	query := u.Query()
	result := query.Has("sign") && strings.HasPrefix(u.RawQuery, "sign=")
	logger.LogDebug("判断是否是ALIST链接结果: %v", result)
	return result
}

// ProxyRequest 执行实际的请求转发
func ProxyRequest(targetURL string, w http.ResponseWriter, r *http.Request, socksProxy *config.SocksProxyConfig, timeout time.Duration, sizeLimit int64) {
	logger.LogDebug("===== 开始代理请求 =====")
	logger.LogDebug("目标URL: %s", targetURL)
	logger.LogDebug("原始请求方法: %s", r.Method)

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logger.LogError("创建请求失败: %v", err)
		http.Error(w, fmt.Sprintf("创建请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	for k, v := range r.Header {
		req.Header[k] = v
		logger.LogDebug("复制请求头: %s = %v", k, v)
	}

	req.Header.Del("Connection")
	req.Header.Del("Accept-Encoding")

	client := getHTTPClient(socksProxy, timeout)

	logger.LogDebug("发送请求到目标服务器")
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("请求失败: %v", err)
		http.Error(w, fmt.Sprintf("请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	logger.LogDebug("收到响应，状态码: %d", resp.StatusCode)
	logger.LogDebug("响应头: %+v", resp.Header)

	contentLength, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err == nil {
		logger.LogDebug("检测到内容长度: %d", contentLength)
		if contentLength > SizeLimit {
			logger.LogError("文件大小超出限制: %d", contentLength)
			http.Error(w, "文件过大，请手动下载。", http.StatusRequestEntityTooLarge)
			return
		}
	}

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)
	logger.LogInfo("开始传输响应内容")

	buf := make([]byte, 32*1024)
	_, err = io.CopyBuffer(&flushWriter{w}, resp.Body, buf)
	if err != nil {
		if isClosedConnectionError(err) {
			logger.LogWarn("客户端断开连接: %v", err)
			return
		}
		logger.LogError("流式传输失败: %v", err)
		http.Error(w, "传输中断", http.StatusInternalServerError)
	} else {
		logger.LogDebug("响应内容传输完成")
	}
}

// isClosedConnectionError 检查是否是连接关闭错误
func isClosedConnectionError(err error) bool {
	result := errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset")
	if result {
		logger.LogDebug("检测到连接关闭错误: %v", err)
	}
	return result
}

// getHTTPClient 获取HTTP客户端
func getHTTPClient(socksProxy *config.SocksProxyConfig, timeout time.Duration) *http.Client {
	if socksProxy != nil && socksProxy.Enabled {
		logger.LogDebug("使用全局SOCKS代理转发请求")
		logger.LogDebug("代理配置: %+v", socksProxy)

		var auth *proxy.Auth
		if socksProxy.Username != "" || socksProxy.Password != "" {
			auth = &proxy.Auth{
				User:     socksProxy.Username,
				Password: socksProxy.Password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp",
			fmt.Sprintf("%s:%d", socksProxy.Host, socksProxy.Port),
			auth,
			proxy.Direct)
		if err != nil {
			logger.LogError("创建SOCKS5拨号器失败: %v", err)
			// 创建不使用代理的客户端
			return &http.Client{
				Timeout: timeout,
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

		return &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					logger.LogInfo("通过代理建立连接到: %s %s", network, addr)
					return dialer.Dial(network, addr)
				},
			},
			Timeout: timeout,
		}
	} else {
		logger.LogInfo("使用直连方式转发请求")
		return &http.Client{
			Timeout: timeout,
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
}