package config

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// TokenConfig holds the configuration for JWT token generation and validation.
type TokenConfig struct {
	secret               string            // Secret key used for signing and verifying JWT tokens.
	expirationTime       time.Duration     // Expiration time for JWT tokens.
	signingMethod        jwt.SigningMethod // Signing method used for JWT tokens.
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// TokenOption is a function type used to configure JWTConfig options.
type TokenOption func(*TokenConfig)

const (
	defaultSecret               string        = "fallback_secure_default_key" // Default secret key (should be overridden in production).
	defaultExpirationTime       time.Duration = 24 * time.Hour                // Default expiration time for JWT tokens (24 hours).
	defaultAccessTokenDuration  time.Duration = 30 * time.Minute
	defaultRefreshTokenDuration time.Duration = 30 * 24 * time.Hour
)

// NewTokenConfig creates a new JWTConfig with default values and applies provided options.
//
// Parameters:
//
//	opts ...JWTOption: A variadic list of JWTOption functions to configure the JWTConfig.
//
// Returns:
//
//	*JWTConfig: A new JWTConfig instance.
func NewTokenConfig(opts ...TokenOption) *TokenConfig {
	config := &TokenConfig{
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
func WithSecret(secret string) TokenOption {
	return func(c *TokenConfig) {
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
func WithExpirationTime(duration time.Duration) TokenOption {
	return func(c *TokenConfig) {
		c.expirationTime = duration
	}
}

func WithAccessTokenTime(duration time.Duration) TokenOption {
	return func(c *TokenConfig) {
		c.accessTokenDuration = duration
	}
}

func WithRefreshTokenExpiration(duration time.Duration) TokenOption {
	return func(c *TokenConfig) {
		c.refreshTokenDuration = duration
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
func WithSigningMethod(method jwt.SigningMethod) TokenOption {
	return func(c *TokenConfig) {
		c.signingMethod = method
	}
}

// Secret returns the secret key from the JWTConfig.
//
// Returns:
//
//	string: The secret key.
func (j *TokenConfig) Secret() string {
	return j.secret
}

// ExpirationTime returns the expiration time from the JWTConfig.
//
// Returns:
//
//	time.Duration: The expiration time.
func (j *TokenConfig) ExpirationTime() time.Duration {
	return j.expirationTime
}

func (j *TokenConfig) RefreshTokenDuration() time.Duration {
	return j.refreshTokenDuration
}

func (j *TokenConfig) AccessTokenDuration() time.Duration {
	return j.accessTokenDuration
}

// SigningMethod returns the signing method from the JWTConfig.
//
// Returns:
//
//	jwt.SigningMethod: The signing method.
func (j *TokenConfig) SigningMethod() jwt.SigningMethod {
	return j.signingMethod
}
