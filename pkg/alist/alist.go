package alist

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"file-proxy/pkg/config"
	"file-proxy/pkg/logger"
)

// AlistResponse Alist API响应结构
type AlistResponse struct {
	Code int `json:"code"`
	Msg  string `json:"message"`
	Data struct {
		URL string `json:"url"`
	} `json:"data"`
}

// GenerateSign 生成HMAC-SHA256签名
// path: 文件路径
// token: Alist令牌
// expire: 过期时间
func GenerateSign(path, token string, expire int) string {
	logger.LogDebug("生成签名: path=%s, expire=%d", path, expire)
	toSign := fmt.Sprintf("%s:%d", path, expire)
	h := hmac.New(sha256.New, []byte(token))
	h.Write([]byte(toSign))
	digest := h.Sum(nil)
	sign := base64.URLEncoding.EncodeToString(digest)
	result := fmt.Sprintf("%s:%d", sign, expire)
	logger.LogDebug("生成的签名: %s", result)
	return result
}

// VerifySign 验证HMAC-SHA256签名
// path: 文件路径
// fullSign: 完整签名
// token: Alist令牌
func VerifySign(path, fullSign, token string) bool {
	logger.LogDebug("验证签名: path=%s, fullSign=%s", path, fullSign)
	parts := strings.Split(fullSign, ":")
	if len(parts) != 2 {
		logger.LogError("签名格式无效，需要两部分，得到 %d 部分", len(parts))
		return false
	}

	receivedSign := parts[0]
	expireStr := parts[1]

	expire, err := strconv.Atoi(expireStr)
	if err != nil {
		logger.LogError("解析过期时间失败: %v", err)
		return false
	}

	// 检查签名是否过期 (0表示永不过期)
	if expire > 0 && time.Now().Unix() > int64(expire) {
		logger.LogError("签名已过期")
		return false
	}

	expectedSign := GenerateSign(path, token, expire)
	expectedSignPart := strings.Split(expectedSign, ":")[0]

	result := hmac.Equal(
		[]byte(strings.TrimRight(receivedSign, "=")),
		[]byte(strings.TrimRight(expectedSignPart, "=")),
	)
	logger.LogInfo("Openlist 验证sign结果: %v", result)
	return result
}

// GetRealURL 获取Alist文件的真实URL
// proxyURL: Alist代理URL
// cfg: 应用配置
func GetRealURL(proxyURL string, cfg *config.Config) (string, error) {
	logger.LogDebug("开始解析Alist代理URL: %s", proxyURL)

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		logger.LogError("URL解析失败: %v", err)
		return "", fmt.Errorf("解析URL失败: %w", err)
	}

	decodedPath, err := url.PathUnescape(parsed.Path)
	if err != nil {
		logger.LogError("URL解码失败: %v", err)
		return "", fmt.Errorf("URL解码失败: %w", err)
	}

	sign := parsed.Query().Get("sign")
	if sign == "" {
		logger.LogError("缺少签名参数")
		return "", errors.New("缺少签名参数")
	}

	if !VerifySign(decodedPath, sign, cfg.AlistToken) {
		logger.LogError("签名验证失败")
		return "", errors.New("签名验证失败")
	}

	apiURL := cfg.AlistAPIURL + "/api/fs/link"
	headers := map[string]string{
		"Authorization": cfg.AlistToken,
		"Content-Type":  "application/json",
	}

	data := map[string]string{"path": decodedPath}
	jsonData, err := json.Marshal(data)
	if err != nil {
		logger.LogError("JSON编码失败: %v", err)
		return "", fmt.Errorf("JSON编码失败: %w", err)
	}

	logger.LogDebug("准备请求Alist API: %s", apiURL)
	logger.LogDebug("请求数据: %s", jsonData)

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		logger.LogError("创建请求失败: %v", err)
		return "", fmt.Errorf("创建请求失败: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: time.Duration(cfg.ProxyTimeout) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("请求Alist API失败: %v", err)
		return "", fmt.Errorf("请求Alist API失败: %w", err)
	}
	defer resp.Body.Close()

	logger.LogDebug("Alist API响应状态码: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		logger.LogError("Alist API返回非200状态码: %d", resp.StatusCode)
		return "", fmt.Errorf("Alist API返回非200状态码: %d", resp.StatusCode)
	}

	var alistResp AlistResponse
	if err := json.NewDecoder(resp.Body).Decode(&alistResp); err != nil {
		logger.LogError("解析Alist响应失败: %v", err)
		return "", fmt.Errorf("解析Alist响应失败: %w", err)
	}

	logger.LogDebug("Alist API响应: %+v", alistResp)

	if alistResp.Code != 200 {
		logger.LogError("Alist API返回错误: %s", alistResp.Msg)
		return "", fmt.Errorf("Alist API返回错误: %s", alistResp.Msg)
	}

	logger.LogDebug("获取到真实URL: %s", alistResp.Data.URL)
	return alistResp.Data.URL, nil
}