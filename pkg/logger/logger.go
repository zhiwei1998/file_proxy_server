package logger

import (
	"log"
	"strings"
)

// 日志级别常量
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

var logLevel = LogLevelInfo // 默认日志级别

// SetLogLevel 设置日志级别
func SetLogLevel(level string) {
	level = strings.ToLower(level)
	if level == LogLevelDebug || level == LogLevelInfo || level == LogLevelWarn || level == LogLevelError {
		logLevel = level
		LogInfo("日志级别已设置为: %s", level)
	} else {
		LogWarn("无效的日志级别: %s，将使用默认级别: %s", level, LogLevelInfo)
	}
}

// GetLogLevel 获取当前日志级别
func GetLogLevel() string {
	return logLevel
}

// LogDebug 输出调试日志
func LogDebug(format string, v ...interface{}) {
	if logLevel == LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

// LogInfo 输出信息日志
func LogInfo(format string, v ...interface{}) {
	if logLevel == LogLevelDebug || logLevel == LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

// LogWarn 输出警告日志
func LogWarn(format string, v ...interface{}) {
	if logLevel == LogLevelDebug || logLevel == LogLevelInfo || logLevel == LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}

// LogError 输出错误日志
func LogError(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}