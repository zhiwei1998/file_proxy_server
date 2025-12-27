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
	"sync"
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
	// 获取下载并发配置
	concurrency := config.AppConfig.DownloadConcurrency
	partSize := config.AppConfig.DownloadPartSize
	// 转换partSize为字节，默认10MB
	if partSize == 0 {
		partSize = 10 * 1024 // 10MB in KB
	}
	partSizeBytes := int64(partSize * 1024)
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

	// 检查是否支持并发下载
	acceptRanges := resp.Header.Get("Accept-Ranges")
	// 如果客户端已经发送了Range头，则不进行额外的并发处理
	clientHasRange := r.Header.Get("Range") != ""
	supportsRange := acceptRanges == "bytes" && contentLength > 0 && concurrency > 1 && !clientHasRange

	if supportsRange {
		logger.LogInfo("服务器支持Range请求，使用并发下载，并发数: %d，分块大小: %d bytes", concurrency, partSizeBytes)
		
		// 复制响应头（并发下载需要特殊处理）
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		// 设置状态码
		w.WriteHeader(resp.StatusCode)
		
		// 实现并发下载
		if err := concurrentDownload(targetURL, w, r, socksProxy, timeout, contentLength, partSizeBytes, concurrency); err != nil {
			logger.LogError("并发下载失败，回退到单线程下载: %v", err)
			// 关闭当前响应体
			resp.Body.Close()
			// 重新发送请求，使用单线程下载
			fallbackToSingleDownload(targetURL, w, r, socksProxy, timeout)
			return
		}
		logger.LogDebug("并发下载完成")
	} else {
		logger.LogInfo("不支持并发下载，使用单线程下载")
		
		// 复制响应头
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		// 设置状态码
		w.WriteHeader(resp.StatusCode)
		
		// 原有的单线程下载逻辑
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
}

// 流式数据结构，用于实时传输下载的数据
type StreamData struct {
	index  int
	data   []byte
	eof    bool
	error  error
}

// concurrentDownload 实现并发下载功能
func concurrentDownload(targetURL string, w http.ResponseWriter, r *http.Request, socksProxy *config.SocksProxyConfig, timeout time.Duration, contentLength, partSizeBytes int64, concurrency int) error {
	// 计算分块数量
	numParts := (contentLength + partSizeBytes - 1) / partSizeBytes
	logger.LogDebug("文件总大小: %d bytes, 分块大小: %d bytes, 总块数: %d", contentLength, partSizeBytes, numParts)

	// 立即刷新响应头，确保客户端不会超时断开连接
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// 创建上下文，用于在客户端断开连接时取消所有下载
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// 创建一个通道来管理要下载的分块索引
	indexChan := make(chan int, numParts)
	// 创建一个通道来处理重试的分块索引
	retryChan := make(chan int, numParts)
	// 创建一个通道来实时传输已下载的数据块
	dataChan := make(chan StreamData, concurrency*2)
	
	// 优化：预填充索引通道，减少启动延迟
	go func() {
		for i := 0; i < int(numParts); i++ {
			indexChan <- i
		}
		close(indexChan) // 在所有索引添加完成后关闭通道
	}()

	// 创建一个互斥锁和条件变量，用于同步数据传输
	var mu sync.Mutex
	var cond = sync.NewCond(&mu)
	
	// 使用滑动窗口机制跟踪已发送的块
	var nextPartToSend = 0 // 下一个要发送的块索引
	var downloadComplete bool = false
	var clientDisconnected bool = false
	var partsSent = make([]bool, numParts) // 标记哪些块已发送

	// 创建一个等待组来等待所有下载完成
	var wg sync.WaitGroup
	client := getHTTPClient(socksProxy, timeout)
	
	// 下载单个块的函数，包含重试逻辑
	downloadPart := func(index int) error {
		// 计算下载范围
		start := int64(index) * partSizeBytes
		end := start + partSizeBytes - 1
		if end >= contentLength {
			end = contentLength - 1
		}
		
		logger.LogDebug("下载块 %d, 范围: %d-%d", index, start, end)
		downloadStartTime := time.Now()

		// 最多重试3次
		for retry := 0; retry < 3; retry++ {
			// 检查客户端是否已断开连接
			mu.Lock()
			if clientDisconnected {
				mu.Unlock()
				return fmt.Errorf("客户端已断开连接")
			}
			mu.Unlock()

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// 创建请求
			req, err := http.NewRequestWithContext(ctx, r.Method, targetURL, nil)
			if err != nil {
				logger.LogError("创建请求失败: %v", err)
				if retry < 2 {
					logger.LogDebug("重试下载块 %d (第 %d 次)", index, retry+1)
					time.Sleep(100 * time.Millisecond * time.Duration(retry+1))
					continue
				}
				return err
			}

			// 复制请求头
			for k, v := range r.Header {
				req.Header[k] = v
			}

			// 设置Range头
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
			req.Header.Del("Connection")
			req.Header.Del("Accept-Encoding")

			// 发送请求
			resp, err := client.Do(req)
			if err != nil {
				logger.LogError("发送请求失败: %v", err)
				// 检查是否是context canceled错误，如果是则立即返回
				if errors.Is(err, context.Canceled) {
					logger.LogDebug("检测到context canceled错误，停止重试")
					return fmt.Errorf("客户端已断开连接")
				}
				if retry < 2 {
					logger.LogDebug("重试下载块 %d (第 %d 次)", index, retry+1)
					time.Sleep(100 * time.Millisecond * time.Duration(retry+1))
					continue
				}
				return err
			}
			
			// 检查响应状态
			if resp.StatusCode != http.StatusPartialContent {
				logger.LogError("服务器不支持Range请求，状态码: %d", resp.StatusCode)
				resp.Body.Close()
				if retry < 2 {
					logger.LogDebug("重试下载块 %d (第 %d 次)", index, retry+1)
					time.Sleep(100 * time.Millisecond * time.Duration(retry+1))
					continue
				}
				return fmt.Errorf("服务器不支持Range请求，状态码: %d", resp.StatusCode)
			}

			// 读取响应内容
			buf := make([]byte, 32*1024)
			var totalRead int64 = 0
			for {
				// 检查客户端是否已断开连接
				mu.Lock()
				if clientDisconnected {
					mu.Unlock()
					resp.Body.Close()
					return fmt.Errorf("客户端已断开连接")
				}
				mu.Unlock()
				
				// 检查上下文是否已取消
				select {
				case <-ctx.Done():
					resp.Body.Close()
					return ctx.Err()
				default:
				}
				
				// 设置读取超时，以便及时响应客户端断开连接
				// 安全地设置读取超时，避免类型断言失败
				if tc, ok := resp.Body.(interface{ SetReadDeadline(time.Time) error }); ok {
					tc.SetReadDeadline(time.Now().Add(30 * time.Second)) // 延长超时时间到30秒
				}
				n, err := resp.Body.Read(buf)
				if n > 0 {
					totalRead += int64(n)
					
					// 创建一个新的切片，并复制数据到这个切片中，避免共享缓冲区导致的数据损坏
					data := make([]byte, n)
					copy(data, buf[:n])
					
					// 实时发送数据到数据通道
					select {
					case dataChan <- StreamData{index: index, data: data, eof: false, error: nil}:
						logger.LogDebug("块 %d 发送了 %d bytes 数据", index, n)
					case <-ctx.Done():
						logger.LogDebug("上下文已取消，停止发送块 %d 数据", index)
						resp.Body.Close()
						return ctx.Err()
					}
				}
				if err != nil {
					if err != io.EOF {
						// 检查是否是客户端断开连接导致的错误
						mu.Lock()
						if clientDisconnected {
							mu.Unlock()
							resp.Body.Close()
							return fmt.Errorf("客户端已断开连接")
						}
						mu.Unlock()
						
						// 检查上下文是否已取消
						if errors.Is(err, context.Canceled) {
							resp.Body.Close()
							return fmt.Errorf("客户端已断开连接")
						}
						
						logger.LogError("读取响应失败: %v", err)
						resp.Body.Close()
						if retry < 2 {
							logger.LogDebug("重试下载块 %d (第 %d 次)", index, retry+1)
							time.Sleep(100 * time.Millisecond * time.Duration(retry+1))
							continue
						}
						return err
					}
					break
				}
			}
			resp.Body.Close()

			// 验证下载的数据大小是否正确
			expectedSize := end - start + 1
			if totalRead != expectedSize {
				logger.LogWarn("下载块 %d 大小不完整，期望: %d bytes, 实际: %d bytes", index, expectedSize, totalRead)
				if retry < 2 {
					logger.LogDebug("重试下载块 %d (第 %d 次)", index, retry+1)
					time.Sleep(100 * time.Millisecond * time.Duration(retry+1))
					continue
				}
			}

			// 只有在成功完成下载且大小正确时才发送EOF标记
			select {
			case dataChan <- StreamData{index: index, data: nil, eof: true, error: nil}:
				logger.LogDebug("块 %d 发送了EOF标记", index)
			case <-ctx.Done():
				logger.LogDebug("上下文已取消，停止发送块 %d EOF", index)
				return ctx.Err()
			}

			elapsedTime := time.Since(downloadStartTime)
			speed := float64(totalRead) / elapsedTime.Seconds() / 1024 / 1024 // MB/s
			logger.LogInfo("完成下载块 %d, 大小: %d bytes, 耗时: %.2f 秒, 速度: %.2f MB/s", index, totalRead, elapsedTime.Seconds(), speed)
			return nil
		}
		return fmt.Errorf("failed to download part %d after 3 retries", index)
	}



	// 启动所有下载线程（包括第一个块）
	wg.Add(concurrency)
	logger.LogDebug("启动 %d 个下载线程", concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			
			for {
				// 从indexChan获取分块索引，如果indexChan关闭则从retryChan获取
				var index int
				var ok bool
				select {
				case index, ok = <-indexChan:
					if !ok {
						// indexChan已关闭，开始处理retryChan
						break
					}
				default:
					// indexChan为空，尝试从retryChan获取
					select {
					case index, ok = <-retryChan:
						if !ok {
							// 两个通道都已关闭，退出循环
							return
						}
					default:
						// 两个通道都为空，检查是否下载完成
					mu.Lock()
					if downloadComplete {
						mu.Unlock()
						return
					}
					mu.Unlock()
					// 短暂休眠后重试
					time.Sleep(200 * time.Millisecond) // 增加休眠时间，减少CPU占用
					continue
					}
				}
				
				// 检查客户端是否已断开连接
				mu.Lock()
				if clientDisconnected {
					mu.Unlock()
					return
				}
				mu.Unlock()
				
				// 下载块
		err := downloadPart(index)
		if err != nil {
			logger.LogError("下载块 %d 失败: %v", index, err)
			
			// 检查客户端是否已断开连接
			mu.Lock()
			if clientDisconnected {
				mu.Unlock()
				return
			}
			mu.Unlock()
			
			// 检查是否是客户端断开连接导致的错误，如果是则立即返回
			if strings.Contains(err.Error(), "客户端已断开连接") {
				logger.LogDebug("检测到客户端断开连接错误，停止重试")
				return
			}
			
			// 将失败的块添加到重试通道
			select {
			case retryChan <- index:
				logger.LogDebug("块 %d 添加到重试队列", index)
			default:
				logger.LogError("重试队列已满，块 %d 重试失败", index)
			}
			continue
		}

		logger.LogInfo("下载线程完成下载块 %d", index)
			}
		}()
	}
	
	// 启动一个goroutine来关闭retryChan和数据通道，当所有下载线程完成后
	go func() {
		wg.Wait()
		close(retryChan)
		close(dataChan)
		mu.Lock()
		downloadComplete = true
		mu.Unlock()
		cond.Signal()
	}()

	// 实时流式传输：使用滑动窗口机制处理数据通道
	logger.LogDebug("开始实时流式传输")
	
	// 创建一个缓冲区来存储每个块的部分数据
	type BlockBuffer struct {
		data     []byte
		received bool
		eof      bool
	}
	blockBuffers := make([]BlockBuffer, numParts)
	
	// 跟踪已完成的块数
	completedBlocks := 0
	
	// 优化：使用带超时的等待机制，避免长时间阻塞
	const waitTimeout = 100 * time.Millisecond // 减少超时时间，更快响应
	
	// 主循环：持续从数据通道接收数据并发送
	for {
		mu.Lock()
		
		// 检查是否应该退出循环
		if nextPartToSend >= int(numParts) {
			// 所有块都已发送完成
			mu.Unlock()
			break
		}
		
		// 获取当前要发送的块的缓冲区
		currentBuffer := &blockBuffers[nextPartToSend]
		
		// 检查当前块是否有数据
		if len(currentBuffer.data) > 0 {
			// 复制数据以便在解锁后发送
			dataToSend := make([]byte, len(currentBuffer.data))
			copy(dataToSend, currentBuffer.data)
			// 清空当前块的缓冲区
			currentBuffer.data = nil
			
			mu.Unlock()
			
			// 立即发送接收到的数据
			logger.LogDebug("发送块 %d 的部分数据, 大小: %d bytes", nextPartToSend, len(dataToSend))
			
			_, err := w.Write(dataToSend)
			if err != nil {
				if isClosedConnectionError(err) {
					logger.LogWarn("客户端断开连接")
					// 通知其他线程客户端断开连接
					mu.Lock()
					clientDisconnected = true
					mu.Unlock()
					cancel() // 取消所有正在进行的下载
					return nil
				}
				logger.LogError("写入响应失败: %v", err)
				return err
			}
			
			// 立即刷新响应，确保数据实时传输
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		} else if currentBuffer.eof {
			// 当前块已完成
			logger.LogDebug("块 %d 已完成传输", nextPartToSend)
			// 检查是否还有未发送的数据
			if len(currentBuffer.data) > 0 {
				// 复制数据以便在解锁后发送
				dataToSend := make([]byte, len(currentBuffer.data))
				copy(dataToSend, currentBuffer.data)
				// 清空当前块的缓冲区
				currentBuffer.data = nil
				
				mu.Unlock()
				
				// 立即发送剩余数据
				logger.LogDebug("发送块 %d 的剩余数据, 大小: %d bytes", nextPartToSend, len(dataToSend))
				
				_, err := w.Write(dataToSend)
				if err != nil {
					if isClosedConnectionError(err) {
						logger.LogWarn("客户端断开连接")
						// 通知其他线程客户端断开连接
						mu.Lock()
						clientDisconnected = true
						mu.Unlock()
						cancel() // 取消所有正在进行的下载
						return nil
					}
					logger.LogError("写入响应失败: %v", err)
					return err
				}
				
				// 立即刷新响应，确保数据实时传输
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				mu.Lock()
			}
			partsSent[nextPartToSend] = true
			nextPartToSend++
			mu.Unlock()
		} else {
			mu.Unlock()
			
			// 从数据通道接收实时数据
			timer := time.NewTimer(waitTimeout)
			select {
			case streamData, ok := <-dataChan:
				timer.Stop()
				if !ok {
					// 数据通道已关闭
					logger.LogDebug("数据通道已关闭")
					// 检查是否还有未发送的数据
					mu.Lock()
					allSent := nextPartToSend >= int(numParts)
					mu.Unlock()
					if allSent {
						break
					}
					// 继续循环，尝试发送剩余数据
					continue
				}
				
				// 检查是否有错误
				if streamData.error != nil {
					logger.LogError("块 %d 下载错误: %v", streamData.index, streamData.error)
					continue
				}
				
				mu.Lock()
				
				// 检查索引是否有效
				if streamData.index < 0 || streamData.index >= int(numParts) {
					mu.Unlock()
					logger.LogError("无效的块索引: %d", streamData.index)
					continue
				}
				
				// 更新块缓冲区
				if streamData.data != nil {
					// 追加新数据到块缓冲区
					blockBuffers[streamData.index].data = append(blockBuffers[streamData.index].data, streamData.data...)
					blockBuffers[streamData.index].received = true
					logger.LogDebug("块 %d 接收了 %d bytes 数据，累计: %d bytes", 
						streamData.index, len(streamData.data), len(blockBuffers[streamData.index].data))
				}
				
				// 检查是否到达块末尾
				if streamData.eof {
					blockBuffers[streamData.index].eof = true
					completedBlocks++
					logger.LogDebug("块 %d 已完成下载", streamData.index)
				}
				
				mu.Unlock()
				
			case <-timer.C:
				// 超时后继续循环，检查是否有数据可发送
				continue
			
			case <-ctx.Done():
				logger.LogDebug("上下文已取消，停止流式传输")
				return nil
			}
		}
	}

	logger.LogDebug("并发下载完成")
	return nil
}

// fallbackToSingleDownload 回退到单线程下载
func fallbackToSingleDownload(targetURL string, w http.ResponseWriter, r *http.Request, socksProxy *config.SocksProxyConfig, timeout time.Duration) {
	logger.LogInfo("开始单线程下载回退")

	// 创建新的请求
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logger.LogError("创建请求失败: %v", err)
		http.Error(w, fmt.Sprintf("创建请求失败: %v", err), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for k, v := range r.Header {
		req.Header[k] = v
	}

	req.Header.Del("Connection")
	req.Header.Del("Accept-Encoding")

	client := getHTTPClient(socksProxy, timeout)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("请求失败: %v", err)
		http.Error(w, fmt.Sprintf("请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	// 传输响应内容
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
		logger.LogDebug("单线程下载回退完成")
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