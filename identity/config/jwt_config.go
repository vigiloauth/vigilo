package config

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTConfig holds the configuration for generating JWT tokens.
type JWTConfig struct {
	secret         string
	expirationTime time.Duration
	signingMethod  jwt.SigningMethod
}

// JWTOption defines a function type for configuring JWTConfig
type JWTOption func(*JWTConfig)

const (
	defaultSecret         string        = "fallback_secure_default_key"
	defaultExpirationTime time.Duration = 24 * time.Hour
)

// NewJWTConfig creates a new JWTConfig with options
func NewJWTConfig(opts ...JWTOption) *JWTConfig {
	config := &JWTConfig{
		secret:         defaultSecret,
		expirationTime: defaultExpirationTime,
		signingMethod:  jwt.SigningMethodHS256,
	}

	for _, opt := range opts {
		opt(config)
	}

	return config
}

// WithSecret sets a custom secret key for JWT
func WithSecret(secret string) JWTOption {
	return func(c *JWTConfig) {
		c.secret = secret
	}
}

// WithExpirationTime sets custom expiration time
func WithExpirationTime(duration time.Duration) JWTOption {
	return func(c *JWTConfig) {
		c.expirationTime = duration
	}
}

// WithSigningMethod sets custom signing method
func WithSigningMethod(method jwt.SigningMethod) JWTOption {
	return func(c *JWTConfig) {
		c.signingMethod = method
	}
}

func (j *JWTConfig) Secret() string {
	return j.secret
}

func (j *JWTConfig) ExpirationTime() time.Duration {
	return j.expirationTime
}

func (j *JWTConfig) SigningMethod() jwt.SigningMethod {
	return j.signingMethod
}
