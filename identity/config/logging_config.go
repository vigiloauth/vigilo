package config

import (
	"fmt"
	"os"
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
)

var levelNames = map[LogLevel]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

var levelByName = map[string]LogLevel{
	"DEBUG": DEBUG,
	"INFO":  INFO,
	"WARN":  WARN,
	"ERROR": ERROR,
}

// colors for terminal output
var colors = map[LogLevel]string{
	DEBUG: "\033[36m", // Cyan
	INFO:  "\033[32m", // Green
	WARN:  "\033[33m", // Yellow
	ERROR: "\033[31m", // Red
}
var colorReset = "\033[0m"

// Logger is our singleton logger implementation
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

	levelUpper := level
	if lvl, exists := levelByName[levelUpper]; exists {
		l.level = lvl
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")

		logLine := fmt.Sprintf("%s[%s] %s%s%s [LOGGER] Log level set to %s",
			colors[INFO], timestamp, colors[INFO], "INFO", colorReset, levelUpper,
		)
		fmt.Fprintln(os.Stdout, logLine)

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
func (l *Logger) log(level LogLevel, module string, format string, args ...any) {
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
		logLine = fmt.Sprintf("%s[%s] %s%s%s [%s] %s",
			colorCode, timestamp, colorCode, levelName, colorReset, module, message)
	} else {
		logLine = fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, levelName, module, message)
	}

	fmt.Fprintln(os.Stdout, logLine)
}

// Debug logs a debug message
func (l *Logger) Debug(module string, format string, args ...any) {
	l.log(DEBUG, module, format, args...)
}

// Info logs an info message
func (l *Logger) Info(module string, format string, args ...any) {
	l.log(INFO, module, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(module string, format string, args ...any) {
	l.log(WARN, module, format, args...)
}

// Error logs an error message
func (l *Logger) Error(module string, format string, args ...any) {
	l.log(ERROR, module, format, args...)
}

// Package-level convenience functions

// Debug logs a debug message
func Debug(module string, format string, args ...any) {
	GetLogger().Debug(module, format, args...)
}

// Info logs an info message
func Info(module string, format string, args ...any) {
	GetLogger().Info(module, format, args...)
}

// Warn logs a warning message
func Warn(module string, format string, args ...any) {
	GetLogger().Warn(module, format, args...)
}

// Error logs an error message
func Error(module string, format string, args ...any) {
	GetLogger().Error(module, format, args...)
}

// SetLevel sets the log level at package level
func SetLevel(level string) {
	GetLogger().SetLevel(level)
}

// SetColorized enables or disables colorized output at package level
func SetColorized(enabled bool) {
	GetLogger().SetColorized(enabled)
}
