package config

import "sync"

// PasswordConfiguration holds the password policy settings.
// It defines the requirements for password complexity and length.
type PasswordConfiguration struct {
	requireUppercase bool
	requireNumber    bool
	requireSymbol    bool
	minimumLength    int
}

var instance *PasswordConfiguration
var once sync.Once

// GetPasswordConfiguration returns the singleton instance of PasswordConfiguration.
// If the instance doesn't exist, it creates one with default settings.
func GetPasswordConfiguration() *PasswordConfiguration {
	once.Do(func() {
		instance = &PasswordConfiguration{
			requireUppercase: false,
			requireNumber:    false,
			requireSymbol:    false,
			minimumLength:    8,
		}
	})
	return instance
}

func (p *PasswordConfiguration) GetRequireUppercase() bool {
	return p.requireUppercase
}

// SetRequireUppercase sets whether passwords must contain an uppercase letter
func (p *PasswordConfiguration) SetRequireUppercase(require bool) *PasswordConfiguration {
	p.requireUppercase = require
	return p
}

func (p *PasswordConfiguration) GetRequireNumber() bool {
	return p.requireNumber
}

// SetRequireNumber sets whether passwords must contain a numeric digit
func (p *PasswordConfiguration) SetRequireNumber(require bool) *PasswordConfiguration {
	p.requireNumber = require
	return p
}

func (p *PasswordConfiguration) GetRequireSymbol() bool {
	return p.requireSymbol
}

// SetRequireSymbol sets whether passwords must contain a special character
func (p *PasswordConfiguration) SetRequireSymbol(require bool) *PasswordConfiguration {
	p.requireSymbol = require
	return p
}

func (p *PasswordConfiguration) GetMinimumLength() int {
	return p.minimumLength
}

// SetMinimumLength sets the minimum required password length
// If the provided length is less than 8, the value will not be updated
// to maintain basic security standards
func (p *PasswordConfiguration) SetMinimumLength(length int) *PasswordConfiguration {
	if length >= 8 {
		p.minimumLength = length
	}
	return p
}

func (p *PasswordConfiguration) Build() *PasswordConfiguration {
	return p
}
