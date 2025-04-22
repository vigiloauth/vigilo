package config

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/internal/common"
)

// TokenConfig holds the configuration for JWT token generation and validation.
type TokenConfig struct {
	secretKey            string            // Secret key used for signing and verifying JWT tokens.
	expirationTime       time.Duration     // Expiration time for JWT tokens in hours
	signingMethod        jwt.SigningMethod // Signing method used for JWT tokens.
	accessTokenDuration  time.Duration     // Access token duration in minutes
	refreshTokenDuration time.Duration     // Refresh token duration in days
	issuer               string

	logger *Logger
	module string
}

// TokenConfigOptions is a function type used to configure JWTConfig options.
type TokenConfigOptions func(*TokenConfig)

const (
	defaultExpirationTime       time.Duration = time.Duration(24) * time.Hour // Default expiration time for JWT tokens (24 hours).
	defaultAccessTokenDuration  time.Duration = time.Duration(30) * time.Minute
	defaultRefreshTokenDuration time.Duration = time.Duration(1) * 24 * time.Hour
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
func NewTokenConfig(opts ...TokenConfigOptions) *TokenConfig {
	cfg := defaultTokenConfig()
	cfg.loadOptions(opts...)
	cfg.logger.Debug(cfg.module, "", "\n\nToken config parameters: %v", cfg.String())
	return cfg
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
func WithSecret(secret string) TokenConfigOptions {
	return func(c *TokenConfig) {
		c.logger.Debug(c.module, "", "Configuring TokenConfig with given secret=[%s]", common.TruncateSensitive(secret))
		c.secretKey = secret
	}
}

// WithExpirationTime configures the expiration time, in minutes, for the Token Config.
//
// Parameters:
//
//	duration time.Duration: The expiration time duration.
//
// Returns:
//
//	JWTOption: A function that configures the expiration time.
func WithExpirationTime(duration time.Duration) TokenConfigOptions {
	return func(c *TokenConfig) {
		if !isInHours(duration) {
			c.logger.Warn(c.module, "", "Token expiration time is not in hours, using default value")
			c.expirationTime = defaultExpirationTime
			return
		}
		c.logger.Debug(c.module, "", "Configuring TokenConfig with expiration time=[%s]", duration)
		c.expirationTime = duration
	}
}

// WithAccessTokenDuration configures the duration, in minutes, for the access token duration.
// Default is 30 minutes.
//
// Parameters:
//
//	duration time.Duration: The expiration time duration.
//
// Returns:
//
//	JWTOption: A function that configures the expiration time.
func WithAccessTokenDuration(duration time.Duration) TokenConfigOptions {
	return func(c *TokenConfig) {
		if !isInMinutes(duration) {
			c.logger.Warn(c.module, "", "Access token duration is not in minutes, using default value")
			c.accessTokenDuration = defaultAccessTokenDuration
			return
		}
		c.logger.Debug(c.module, "", "Configuring TokenConfig with access token duration=[%s]", duration)
		c.accessTokenDuration = duration
	}
}

// WithRefreshTokenDuration configures the duration, in days, for the refresh token duration.
// Default is 30 days.
//
// Parameters:
//
//	duration time.Duration: The expiration time duration.
//
// Returns:
//
//	JWTOption: A function that configures the expiration time.
func WithRefreshTokenDuration(duration time.Duration) TokenConfigOptions {
	return func(c *TokenConfig) {
		c.logger.Debug(c.module, "", "Configuring TokenConfig with refresh token duration=[%s]", duration)
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
func WithSigningMethod(method jwt.SigningMethod) TokenConfigOptions {
	return func(c *TokenConfig) {
		c.logger.Debug(c.module, "", "Configuring TokenConfig with signing method=[%s]", method.Alg())
		c.signingMethod = method
	}
}

// SecretKey returns the secret key from the JWTConfig.
//
// Returns:
//
//	string: The secret key.
func (j *TokenConfig) SecretKey() string {
	return j.secretKey
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

func (j *TokenConfig) Issuer() string {
	return j.issuer
}

func (j *TokenConfig) String() string {
	return fmt.Sprintf(
		"\n\tSigningMethod: %s\n"+
			"\tExpirationTime: %s\n"+
			"\tRefreshTokenDuration: %s\n"+
			"\tAccessTokenDuration: %s\n",
		j.signingMethod.Alg(),
		j.expirationTime,
		j.refreshTokenDuration,
		j.accessTokenDuration,
	)
}

func defaultTokenConfig() *TokenConfig {
	secretKey := os.Getenv(common.TokenSecretKeyENV)
	issuer := os.Getenv(common.TokenIssuerENV)
	return &TokenConfig{
		secretKey:            secretKey,
		issuer:               issuer,
		expirationTime:       defaultExpirationTime,
		accessTokenDuration:  defaultAccessTokenDuration,
		refreshTokenDuration: defaultRefreshTokenDuration,
		signingMethod:        jwt.SigningMethodHS256,
		logger:               GetLogger(),
		module:               "Token Config",
	}
}

func (cfg *TokenConfig) loadOptions(opts ...TokenConfigOptions) {
	if len(opts) > 0 {
		cfg.logger.Info(cfg.module, "", "Creating token config with %d options", len(opts))
		for _, opt := range opts {
			opt(cfg)
		}
	} else {
		cfg.logger.Info(cfg.module, "", "Using default token config")
	}
}
