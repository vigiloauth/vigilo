package config

const defaultRequiredPasswordLength int = 5

type PasswordConfig struct {
	requireUpper  bool
	requireNumber bool
	requireSymbol bool
	minLength     int
}

type PasswordConfigOption func(*PasswordConfig)

func NewPasswordConfig(opts ...PasswordConfigOption) *PasswordConfig {
	pc := &PasswordConfig{
		requireUpper:  false,
		requireNumber: false,
		requireSymbol: false,
		minLength:     defaultRequiredPasswordLength,
	}

	for _, opt := range opts {
		opt(pc)
	}

	return pc
}

func WithUppercase() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireUpper = true
	}
}

func WithNumber() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireNumber = true
	}
}

func WithSymbol() PasswordConfigOption {
	return func(pc *PasswordConfig) {
		pc.requireSymbol = true
	}
}

func WithMinLength(length int) PasswordConfigOption {
	return func(pc *PasswordConfig) {
		if length > defaultRequiredPasswordLength {
			pc.minLength = length
		}
	}
}

func (pc *PasswordConfig) RequireUppercase() bool {
	return pc.requireUpper
}

func (pc *PasswordConfig) RequireNumber() bool {
	return pc.requireNumber
}

func (pc *PasswordConfig) RequireSymbol() bool {
	return pc.requireSymbol
}

func (pc *PasswordConfig) MinLength() int {
	return pc.minLength
}
