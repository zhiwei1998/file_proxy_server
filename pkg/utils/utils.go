package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"

	"golang.org/x/net/proxy"
)

// FlushWriter 实现http.ResponseWriter接口，并自动调用Flush
// 用于支持流式传输

type FlushWriter struct {
	W http.ResponseWriter
}

// Write 重写Write方法，自动调用Flush
// p: 要写入的数据
func (fw *FlushWriter) Write(p []byte) (int, error) {
	n, err := fw.W.Write(p)
	if f, ok := fw.W.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}

// IsClosedConnectionError 检查是否是连接关闭错误
// err: 要检查的错误
func IsClosedConnectionError(err error) bool {
	result := errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "broken pipe") ||
		strings.Contains(err.Error(), "connection reset")
	if result {
		logger.LogDebug("检测到连接关闭错误: %v", err)
	}
	return result
}

// TestProxyConnectivity 测试代理连通性
// proxyConfig: 代理配置
// cfg: 应用配置
func TestProxyConnectivity(proxyConfig *config.SocksProxyConfig, cfg *config.Config) bool {
	logger.LogDebug("开始测试代理连通性 -> %s:%d", proxyConfig.Host, proxyConfig.Port)

	var auth *proxy.Auth
	if proxyConfig.Username != "" || proxyConfig.Password != "" {
		auth = &proxy.Auth{
			User:     proxyConfig.Username,
			Password: proxyConfig.Password,
		}
	}
	dialer, err := proxy.SOCKS5("tcp", 
		fmt.Sprintf("%s:%d", proxyConfig.Host, proxyConfig.Port), 
		auth, 
		proxy.Direct)
	if err != nil {
		logger.LogError("创建SOCKS5拨号器失败: %v", err)
		return false
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				logger.LogInfo("通过代理建立连接到: %s %s", network, addr)
				return dialer.Dial(network, addr)
			},
		},
		Timeout: time.Duration(cfg.ProxyTimeout) * time.Second,
	}

	logger.LogDebug("发送测试请求到: %s", cfg.TestURL)
	resp, err := httpClient.Get(cfg.TestURL)
	if err != nil {
		logger.LogError("测试请求失败: %v", err)
		return false
	}
	defer resp.Body.Close()

	logger.LogDebug("代理测试成功，响应状态码: %d", resp.StatusCode)
	return resp.StatusCode == http.StatusOK
}