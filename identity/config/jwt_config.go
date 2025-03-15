package config

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type JWTConfig struct {
	secret         string
	expirationTime time.Duration
	signingMethod  jwt.SigningMethod
}

type JWTOption func(*JWTConfig)

const (
	defaultSecret         string        = "fallback_secure_default_key"
	defaultExpirationTime time.Duration = 24 * time.Hour
)

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

func WithSecret(secret string) JWTOption {
	return func(c *JWTConfig) {
		c.secret = secret
	}
}

func WithExpirationTime(duration time.Duration) JWTOption {
	return func(c *JWTConfig) {
		c.expirationTime = duration
	}
}

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
