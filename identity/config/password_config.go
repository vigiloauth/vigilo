package config

import (
	"sync"
)

// PasswordConfig holds the password policy settings.
type PasswordConfig struct {
	mu            sync.RWMutex
	requireUpper  bool
	requireNumber bool
	requireSymbol bool
	minLength     int
}

// Singleton management
var (
	instance *PasswordConfig
	once     sync.Once
)

const defaultRequiredPasswordLength int = 5

// GetPasswordConfiguration returns the singleton instance of PasswordConfiguration with default settings.
// These defaults include a minimum length password of 8, and optional uppercase, number, and symbol.
// The return configuration can be modified as needed.
func GetPasswordConfiguration() *PasswordConfiguration {
	once.Do(func() {
		instance = &PasswordConfig{
			requireUpper:  false,
			requireNumber: false,
			requireSymbol: false,
			minLength:     defaultRequiredPasswordLength,
		}
	})
	return instance
}

// ConfigurePasswordPolicy allows configuring the singleton instance
func (pc *PasswordConfig) ConfigurePasswordPolicy(opts ...PasswordConfigOption) *PasswordConfig {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for _, opt := range opts {
		opt(pc)
	}

	return pc
}

// PasswordConfigOption allows functional configuration
type PasswordConfigOption func(*PasswordConfig)

// WithUppercase adds uppercase requirement
func WithUppercase() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireUpper = true
	}
}

// WithNumber adds number requirement
func WithNumber() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireNumber = true
	}
}

// WithSymbol adds symbol requirement
func WithSymbol() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireSymbol = true
	}
}

// WithMinLength sets minimum password length
func WithMinLength(length int) PasswordConfigOption {
	return func(pc *PasswordConfig) {
		if length > defaultRequiredPasswordLength {
			pc.minLength = length
		}
	}
}

// Getters with thread-safe read access
func (pc *PasswordConfig) RequireUppercase() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.requireUpper
}

func (pc *PasswordConfig) RequireNumber() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.requireNumber
}

func (pc *PasswordConfig) RequireSymbol() bool {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.requireSymbol
}

func (pc *PasswordConfig) MinLength() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return pc.minLength
}
