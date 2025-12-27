package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"file-proxy/pkg/alist"
	"file-proxy/pkg/cache"
	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"
	"file-proxy/pkg/proxy"
	"file-proxy/pkg/redirect"
	"file-proxy/pkg/utils"
)

const (
	sizeLimit = 1024 * 1024 * 1024 * 999
)

var (
	globalSocksProxy *config.SocksProxyConfig
	appConfig        *config.Config
)

func main() {
	args, err := config.ParseArguments()
	if err != nil {
		logger.LogError("参数解析错误: %v\n使用 --help 查看帮助", err)
		os.Exit(1)
	}

	if args.GenerateConfig {
		if err := config.GenerateConfigFile(args.ConfigPath); err != nil {
			logger.LogError("生成配置文件失败: %v", err)
			os.Exit(1)
		}
		logger.LogInfo("配置文件已生成: %s", args.ConfigPath)
		os.Exit(0)
	}

	// 初始化配置
	config.InitConfig()

	// 加载配置
	err = config.LoadConfig(args.ConfigPath, &args)
	if err != nil {
		logger.LogWarn("加载配置文件失败: %v，将使用默认配置", err)
	} else {
		logger.LogInfo("配置文件加载成功: %s", args.ConfigPath)
	}
	appConfig = &config.AppConfig

	// 设置日志级别
	logger.SetLogLevel(appConfig.LogLevel)

	logger.LogInfo("===== 启动服务 =====")
	logger.LogDebug("命令行参数: %+v", args)
	logger.LogDebug("应用配置: %+v", appConfig)

	// 启动缓存清理任务
	if appConfig.EnableCache > 0 {
		cache.CleanupExpiredCache()
		logger.LogInfo("缓存自动清理任务已启动，每30分钟运行一次")
	}

	// SOCKS代理配置
	if args.SocksHost != "" && args.SocksPort > 0 {
		globalSocksProxy = &config.SocksProxyConfig{
			Host:     args.SocksHost,
			Port:     args.SocksPort,
			Username: args.SocksUsername,
			Password: args.SocksPassword,
			Enabled:  true,
		}

		logger.LogInfo("全局SOCKS代理配置: %+v", globalSocksProxy)

		if !utils.TestProxyConnectivity(globalSocksProxy, appConfig) {
			logger.LogWarn("代理测试失败，将禁用代理功能")
			globalSocksProxy.Enabled = false
		}
	}

	// DNS配置和Alist初始化暂时不需要

	// 设置路由
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

	logger.LogInfo("启动服务，监听 %s:%d", args.Host, args.Port)
	if err := server.ListenAndServe(); err != nil {
		logger.LogError("服务器启动失败: %v", err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	logger.LogDebug("处理根路径请求")
	w.Write([]byte("欢迎使用文件代理服务器！请提供有效的文件URL。"))
}

// 专门处理带url和path参数的请求 - 等待获取最终URL后再返回给客户端
func handleURLWithParams(w http.ResponseWriter, r *http.Request) {
	logger.LogDebug("处理带参数的URL请求")

	urlParam := r.URL.Query().Get("url")
	pathParam := r.URL.Query().Get("path")
	scParam := r.URL.Query().Get("sc")

	// 清理path中的查询参数（不保留sign等参数）
	cleanPath := scParam

	// 只有当提供了sc参数且path匹配时才处理缓存和302跳转
	if scParam != "" {
		scParam = scParam[strings.LastIndex(scParam, "/")+1:]
		cleanPath = strings.Trim(cleanPath, "/")

		// 构建目标URL（不保留任何原始查询参数）
		targetURL := urlParam

		logger.LogDebug("转换参数: url=%s, sc=%s, path=%s", urlParam, scParam, pathParam)
		logger.LogDebug("转换结果: %s", targetURL)

		// 检查是否启用了重定向
		if appConfig.EnableRedirect {
			// 启用重定向时的逻辑：进行服务器端重定向追踪并返回最终URL

			// 如果启用了缓存，先检查缓存
			if appConfig.EnableCache > 0 {
				cacheKey := cache.GenerateCacheKey(urlParam, scParam, pathParam)
				cachedURL, found := cache.GetFromCache(cacheKey)
				if found {
					logger.LogInfo("命中缓存：%s", cachedURL)
					// 返回缓存的URL
					w.Header().Set("Location", cachedURL)
					w.WriteHeader(http.StatusFound)
					w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>正在重定向到最终下载链接...</p></body></html>`, cachedURL)))
					return
				}
				logger.LogInfo("缓存未命中，需要获取URL")
			} else {
				logger.LogInfo("缓存功能已禁用")
			}

			// 使用更可靠的方式获取最终URL，确保服务器端处理所有跳转
			finalURL, err := redirect.FollowRedirects(targetURL, appConfig, globalSocksProxy)

			if err != nil {
				logger.LogWarn("重定向追踪遇到错误: %v，将使用原始URL作为备选", err)
				// 如果追踪失败，使用原始URL作为备选
				finalURL = targetURL
			} else {
				logger.LogDebug("服务器端成功完成所有重定向追踪，获取到最终URL")
			}

			logger.LogInfo("最终重定向URL: %s", finalURL)

			// 如果启用了缓存，更新缓存
			if appConfig.EnableCache > 0 {
				cacheKey := cache.GenerateCacheKey(urlParam, scParam, pathParam)
				cache.UpdateCache(cacheKey, finalURL, appConfig)
				logger.LogInfo("已缓存最终URL，有效期%d分钟", appConfig.EnableCache)
			}

			// 返回302响应，让客户端跳转到最终URL
			logger.LogDebug("返回302响应，让客户端跳转到最终URL: %s", finalURL)
			w.Header().Set("Location", finalURL)
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>正在重定向到最终下载链接...</p></body></html>`, finalURL)))
		} else {
			// 禁用重定向时的逻辑：仍然返回302响应让客户端自行跳转到拼接的地址
			logger.LogInfo("重定向功能已禁用，返回302响应让客户端跳转到拼接的地址: %s", targetURL)

			// 返回302响应，让客户端自行访问拼接的地址
			w.Header().Set("Location", targetURL)
			w.WriteHeader(http.StatusFound)
			w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>正在重定向到目标地址...</p></body></html>`, targetURL)))
		}
		return
	}

	// 当sc参数未提供或path不匹配时，使用原始URL
	logger.LogInfo("sc参数未提供或path不匹配，使用原始URL")
	targetURL := urlParam

	// 根据配置决定是重定向还是返回URL文本
	if appConfig.EnableRedirect {
		// 启用重定向时，返回302响应
		logger.LogInfo("返回302响应，让客户端跳转到原始URL: %s", targetURL)
		w.Header().Set("Location", targetURL)
		w.WriteHeader(http.StatusFound)
		// 添加一个简单的HTML提示，以防某些客户端不自动重定向
	} else {
		// 禁用重定向时，仍然返回302响应让客户端自行跳转到原始地址
		logger.LogInfo("重定向功能已禁用，返回302响应让客户端跳转到原始URL: %s", targetURL)
		w.Header().Set("Location", targetURL)
		w.WriteHeader(http.StatusFound)
		w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>正在重定向到目标地址...</p></body></html>`, targetURL)))
		return
	}
	w.Write([]byte(fmt.Sprintf(`<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body><p>正在重定向到最终下载链接...</p></body></html>`, targetURL)))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	logger.LogDebug("===== 开始处理新请求 =====")
	logger.LogDebug("原始请求方法: %s", r.Method)
	logger.LogInfo("原始请求URL: %s", r.URL.String())
	logger.LogDebug("原始请求头: %+v", r.Header)

	// 原有逻辑保持不变
	rawPath := r.URL.EscapedPath()
	logger.LogDebug("原始编码路径: %s", rawPath)

	rawPath = strings.TrimPrefix(rawPath, "/")
	logger.LogDebug("处理后路径: %s", rawPath)

	if proxy.HasSignParamStrict(r.URL.String()) {
		logger.LogDebug("检测到Alist签名参数")
		logger.LogDebug("原始查询参数: %s", r.URL.String())

		realURL, err := alist.GetRealURL(r.URL.String(), appConfig)
		if err != nil {
			logger.LogError("Alist签名验证失败: %v", err)
			http.Error(w, "Alist签名验证失败", http.StatusBadRequest)
			return
		}
		logger.LogInfo("从Alist获取到真实URL: %s", realURL)
		proxy.ProxyRequest(realURL, w, r, globalSocksProxy, time.Duration(appConfig.ProxyTimeout)*time.Second, sizeLimit)
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

	// URL格式验证已在ProxyRequest内部处理
	logger.LogDebug("URL格式验证通过: %s", targetURL)

	logger.LogDebug("准备转发请求到目标URL: %s", targetURL)
	proxy.ProxyRequest(targetURL, w, r, globalSocksProxy, time.Duration(appConfig.ProxyTimeout)*time.Second, sizeLimit)
}
