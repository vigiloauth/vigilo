package config

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

var levelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
	FATAL: "FATAL",
}

var levelByName = map[string]LogLevel{
	"DEBUG": DEBUG,
	"INFO":  INFO,
	"WARN":  WARN,
	"ERROR": ERROR,
	"FATAL": FATAL,
}

// colors for terminal output
var colors = map[LogLevel]string{
	DEBUG: "\033[36m", // Cyan
	INFO:  "\033[32m", // Green
	WARN:  "\033[33m", // Yellow
	ERROR: "\033[31m", // Red
	FATAL: "\033[31m", // Red
}
var colorReset = "\033[0m"

// Logger is base application logger.
type Logger struct {
	level     LogLevel
	colorized bool
	mu        sync.RWMutex
}

var (
	instance *Logger
	once     sync.Once
)

// GetLogger returns the singleton logger instance
func GetLogger() *Logger {
	once.Do(func() {
		instance = &Logger{
			level:     INFO,
			colorized: true,
		}
	})
	return instance
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	levelUpper := strings.ToUpper(level)
	if lvl, exists := levelByName[levelUpper]; exists {
		l.level = lvl
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")

		logLine := fmt.Sprintf("%s[%s] %s%s%s [LOGGER] Log level set to %s",
			colors[INFO], timestamp, colors[INFO], "INFO", colorReset, levelUpper,
		)
		fmt.Fprintln(os.Stdout, logLine)
		if levelUpper == "DEBUG" {
			logLine := fmt.Sprintf("%s[%s] %s%s%s [LOGGER] It is highly recommended to disable DEBUG logs in production environments",
				colors[WARN], timestamp, colors[WARN], "WARN", colorReset,
			)
			fmt.Fprintln(os.Stdout, logLine)
		}

	} else {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		logLine := fmt.Sprintf("%s[%s] %s%s%s [LOGGER] Invalid log level: %s. Using INFO",
			colors[WARN], timestamp, colors[WARN], "WARN", colorReset, level,
		)
		fmt.Fprintln(os.Stdout, logLine)
	}
}

// SetColorized enables or disables colorized output
func (l *Logger) SetColorized(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.colorized = enabled
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return levelNames[l.level]
}

// log logs a message with the given level and module name
// log logs a message with the given level, module name, and optional requestID
func (l *Logger) log(level LogLevel, module string, requestID string, format string, args ...any) {
	l.mu.RLock()
	loggerLevel := l.level
	colorized := l.colorized
	l.mu.RUnlock()

	if level < loggerLevel {
		return
	}

	now := time.Now()
	timestamp := now.Format("2006-01-02 15:04:05.000")
	levelName := levelNames[level]

	message := fmt.Sprintf(format, args...)

	var logLine string
	if colorized {
		colorCode := colors[level]
		// Include requestID if provided
		if requestID != "" {
			logLine = fmt.Sprintf("%s[%s] %s [RequestID=%s] %s%s [%s] %s",
				colorCode, timestamp, levelName, requestID, colorCode, colorReset, module, message)
		} else {
			logLine = fmt.Sprintf("%s[%s] %s%s%s [%s] %s",
				colorCode, timestamp, colorCode, levelName, colorReset, module, message)
		}
	} else {
		// Include requestID if provided
		if requestID != "" {
			logLine = fmt.Sprintf("[%s] [RequestID=%s] [%s] [%s] %s", timestamp, requestID, levelName, module, message)
		} else {
			logLine = fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, levelName, module, message)
		}
	}

	fmt.Fprintln(os.Stdout, logLine)
}

// Debug logs a debug message
func (l *Logger) Debug(module string, requestID string, format string, args ...any) {
	l.log(DEBUG, module, requestID, format, args...)
}

// Info logs an info message
func (l *Logger) Info(module string, requestID string, format string, args ...any) {
	l.log(INFO, module, requestID, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(module string, requestID string, format string, args ...any) {
	l.log(WARN, module, requestID, format, args...)
}

// Error logs an error message
func (l *Logger) Error(module string, requestID string, format string, args ...any) {
	l.log(ERROR, module, requestID, format, args...)
}

func (l *Logger) Fatal(module string, requestID string, format string, args ...any) {
	l.log(FATAL, module, requestID, format, args...)
	os.Exit(1)
}

// Package-level convenience functions

// Debug logs a debug message
func Debug(module string, requestID string, format string, args ...any) {
	GetLogger().Debug(module, requestID, format, args...)
}

// Info logs an info message
func Info(module string, requestID string, format string, args ...any) {
	GetLogger().Info(module, requestID, format, args...)
}

// Warn logs a warning message
func Warn(module string, requestID string, format string, args ...any) {
	GetLogger().Warn(module, requestID, format, args...)
}

// Error logs an error message
func Error(module string, requestID string, format string, args ...any) {
	GetLogger().Error(module, requestID, format, args...)
}

func Fatal(module string, requestID string, format string, args ...any) {
	GetLogger().Fatal(module, requestID, format, args...)
}

// SetLevel sets the log level at package level
func SetLevel(level string) {
	GetLogger().SetLevel(level)
}

// SetColorized enables or disables colorized output at package level
func SetColorized(enabled bool) {
	GetLogger().SetColorized(enabled)
}
