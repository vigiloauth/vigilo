package config

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTConfig holds the configuration for JWT token generation and validation.
type JWTConfig struct {
	secret         string            // Secret key used for signing and verifying JWT tokens.
	expirationTime time.Duration     // Expiration time for JWT tokens.
	signingMethod  jwt.SigningMethod // Signing method used for JWT tokens.
}

// JWTOption is a function type used to configure JWTConfig options.
type JWTOption func(*JWTConfig)

const (
	defaultSecret         string        = "fallback_secure_default_key" // Default secret key (should be overridden in production).
	defaultExpirationTime time.Duration = 24 * time.Hour                // Default expiration time for JWT tokens (24 hours).
)

// NewJWTConfig creates a new JWTConfig with default values and applies provided options.
//
// Parameters:
//
//	opts ...JWTOption: A variadic list of JWTOption functions to configure the JWTConfig.
//
// Returns:
//
//	*JWTConfig: A new JWTConfig instance.
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

// WithSecret configures the secret key for the JWTConfig.
//
// Parameters:
//
//	secret string: The secret key to use.
//
// Returns:
//
//	JWTOption: A function that configures the secret key.
func WithSecret(secret string) JWTOption {
	return func(c *JWTConfig) {
		c.secret = secret
	}
}

// WithExpirationTime configures the expiration time for the JWTConfig.
//
// Parameters:
//
//	duration time.Duration: The expiration time duration.
//
// Returns:
//
//	JWTOption: A function that configures the expiration time.
func WithExpirationTime(duration time.Duration) JWTOption {
	return func(c *JWTConfig) {
		c.expirationTime = duration
	}
}

// WithSigningMethod configures the signing method for the JWTConfig.
//
// Parameters:
//
//	method jwt.SigningMethod: The signing method to use.
//
// Returns:
//
//	JWTOption: A function that configures the signing method.
func WithSigningMethod(method jwt.SigningMethod) JWTOption {
	return func(c *JWTConfig) {
		c.signingMethod = method
	}
}

// Secret returns the secret key from the JWTConfig.
//
// Returns:
//
//	string: The secret key.
func (j *JWTConfig) Secret() string {
	return j.secret
}

// ExpirationTime returns the expiration time from the JWTConfig.
//
// Returns:
//
//	time.Duration: The expiration time.
func (j *JWTConfig) ExpirationTime() time.Duration {
	return j.expirationTime
}

// SigningMethod returns the signing method from the JWTConfig.
//
// Returns:
//
//	jwt.SigningMethod: The signing method.
func (j *JWTConfig) SigningMethod() jwt.SigningMethod {
	return j.signingMethod
}
