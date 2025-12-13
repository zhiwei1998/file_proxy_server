package cache

import (
	"fmt"
	"sync"
	"time"

	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"
)

// CacheItem 缓存项结构
type CacheItem struct {
	FinalURL   string
	ExpireTime time.Time
}

// URL重定向缓存
var (
	redirectCache = make(map[string]*CacheItem)
	cacheMutex    = &sync.RWMutex{}
)

// GetCacheDuration 获取当前配置的缓存时长
// cfg: 应用配置
func GetCacheDuration(cfg *config.Config) time.Duration {
	if cfg.EnableCache <= 0 {
		return 0
	}
	return time.Duration(cfg.EnableCache) * time.Minute
}

// GenerateCacheKey 生成缓存键
// urlParam: URL参数
// scParam: 签名参数
// pathParam: 路径参数
func GenerateCacheKey(urlParam, scParam, pathParam string) string {
	return fmt.Sprintf("%s|%s|%s", urlParam, scParam, pathParam)
}

// GetFromCache 从缓存获取最终URL
// key: 缓存键
func GetFromCache(key string) (string, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	item, exists := redirectCache[key]
	if !exists {
		return "", false
	}

	// 检查是否过期
	if time.Now().After(item.ExpireTime) {
		return "", false
	}

	logger.LogDebug("从缓存获取到最终URL: %s", item.FinalURL)
	return item.FinalURL, true
}

// UpdateCache 更新缓存
// key: 缓存键
// finalURL: 最终URL
// cfg: 应用配置
func UpdateCache(key, finalURL string, cfg *config.Config) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// 获取缓存时长
	duration := GetCacheDuration(cfg)
	if duration <= 0 {
		return // 缓存被禁用
	}

	redirectCache[key] = &CacheItem{
		FinalURL:   finalURL,
		ExpireTime: time.Now().Add(duration),
	}
	logger.LogDebug("更新缓存: key=%s, finalURL=%s, expireTime=%v", key, finalURL, redirectCache[key].ExpireTime)
}

// CleanupExpiredCache 清理过期缓存的函数
// 每30分钟执行一次
func CleanupExpiredCache() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()

		for {
			<-ticker.C
			cacheMutex.Lock()
			now := time.Now()
			count := 0
			for k, v := range redirectCache {
				if now.After(v.ExpireTime) {
					delete(redirectCache, k)
					count++
				}
			}
			cacheMutex.Unlock()
			if count > 0 {
				logger.LogInfo("清理了 %d 个过期缓存项", count)
			}
		}
	}()
}
