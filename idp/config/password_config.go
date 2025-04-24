package config

import (
	"fmt"
)

const defaultRequiredPasswordLength int = 5

// PasswordConfig holds the configuration for password complexity requirements.
type PasswordConfig struct {
	requireUpper  bool // Indicates whether uppercase letters are required.
	requireNumber bool // Indicates whether numbers are required.
	requireSymbol bool // Indicates whether symbols are required.
	minLength     int  // Minimum required password length.
	logger        *Logger
	module        string
}

// PasswordConfigOptions is a function type used to configure PasswordConfig options.
type PasswordConfigOptions func(*PasswordConfig)

// NewPasswordConfig creates a new PasswordConfig with default values and applies provided options.
//
// Parameters:
//
//	opts ...PasswordConfigOption: A variadic list of PasswordConfigOption functions to configure the PasswordConfig.
//
// Returns:
//
//	*PasswordConfig: A new PasswordConfig instance.
func NewPasswordConfig(opts ...PasswordConfigOptions) *PasswordConfig {
	cfg := defaultPasswordConfig()
	cfg.loadOptions(opts...)
	cfg.logger.Debug(cfg.module, "\n\nPassword config parameters: %s", cfg.String())
	return cfg
}

// WithUppercase configures the PasswordConfig to require uppercase letters.
//
// Returns:
//
//	PasswordConfigOption: A function that configures the uppercase requirement.
func WithUppercase() PasswordConfigOptions {
	return func(pc *PasswordConfig) {
		pc.logger.Info(pc.module, "", "Configuring PasswordConfig to require an uppercase")
		pc.requireUpper = true
	}
}

// WithNumber configures the PasswordConfig to require numbers.
//
// Returns:
//
//	PasswordConfigOption: A function that configures the number requirement.
func WithNumber() PasswordConfigOptions {
	return func(pc *PasswordConfig) {
		pc.logger.Info(pc.module, "", "Configuring PasswordConfig to require a number")
		pc.requireNumber = true
	}
}

// WithSymbol configures the PasswordConfig to require symbols.
//
// Returns:
//
//	PasswordConfigOption: A function that configures the symbol requirement.
func WithSymbol() PasswordConfigOptions {
	return func(pc *PasswordConfig) {
		pc.logger.Info(pc.module, "", "Configuring PasswordConfig to require a symbol")
		pc.requireSymbol = true
	}
}

// WithMinLength configures the minimum required password length for the PasswordConfig.
//
// Parameters:
//
//	length int: The minimum password length.
//
// Returns:
//
//	PasswordConfigOption: A function that configures the minimum length.
func WithMinLength(length int) PasswordConfigOptions {
	return func(pc *PasswordConfig) {
		if length > defaultRequiredPasswordLength {
			pc.logger.Info(pc.module, "", "Configuring PasswordConfig minimum length=[%d]", length)
			pc.minLength = length
		}
	}
}

// RequireUppercase returns whether uppercase letters are required from the PasswordConfig.
//
// Returns:
//
//	bool: True if uppercase letters are required, false otherwise.
func (pc *PasswordConfig) RequireUppercase() bool {
	return pc.requireUpper
}

// RequireNumber returns whether numbers are required from the PasswordConfig.
//
// Returns:
//
//	bool: True if numbers are required, false otherwise.
func (pc *PasswordConfig) RequireNumber() bool {
	return pc.requireNumber
}

// RequireSymbol returns whether symbols are required from the PasswordConfig.
//
// Returns:
//
//	bool: True if symbols are required, false otherwise.
func (pc *PasswordConfig) RequireSymbol() bool {
	return pc.requireSymbol
}

// MinLength returns the minimum required password length from the PasswordConfig.
//
// Returns:
//
//	int: The minimum required password length.
func (pc *PasswordConfig) MinLength() int {
	return pc.minLength
}

func (pc *PasswordConfig) String() string {
	return fmt.Sprintf(
		"\n\tRequireUppercase: %t\n"+
			"\tRequireNumber: %t\n"+
			"\tRequireSymbol: %t\n"+
			"\tMinLength: %d\n",
		pc.requireUpper,
		pc.requireNumber,
		pc.requireSymbol,
		pc.minLength,
	)
}

func defaultPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		requireUpper:  false,
		requireNumber: false,
		requireSymbol: false,
		minLength:     defaultRequiredPasswordLength,
		logger:        GetLogger(),
		module:        "Password Config",
	}
}

func (cfg *PasswordConfig) loadOptions(opts ...PasswordConfigOptions) {
	if len(opts) > 0 {
		cfg.logger.Info(cfg.module, "", "Creating password config with %d options", len(opts))
		for _, opt := range opts {
			opt(cfg)
		}
	} else {
		cfg.logger.Info(cfg.module, "", "Using default password config")
	}
}
