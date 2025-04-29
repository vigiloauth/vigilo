package config

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
)

// TokenConfig holds the configuration for JWT token generation and validation.
type TokenConfig struct {
	privateKey           *rsa.PrivateKey // Secret key used for signing and verifying JWT tokens.
	publicKey            *rsa.PublicKey  // Public key used for verifying JWT tokens.
	keyID                string          // Key ID used to identify the key.
	expirationTime       time.Duration   // Expiration time for JWT tokens in hours
	accessTokenDuration  time.Duration   // Access token duration in minutes
	refreshTokenDuration time.Duration   // Refresh token duration in days
	issuer               string

	logger *Logger
	module string
}

// TokenConfigOptions is a function type used to configure JWTConfig options.
type TokenConfigOptions func(*TokenConfig)

const (
	defaultExpirationTime       time.Duration = time.Duration(24) * time.Hour
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

// SecretKey returns the secret key from the JWTConfig.
//
// Returns:
//
//	string: The secret key.
func (j *TokenConfig) SecretKey() *rsa.PrivateKey {
	return j.privateKey
}

// PublicKey returns the public key from the JWTConfig.
//
// Returns:
//
//	*rsa.PublicKey: The public key.
func (j *TokenConfig) PublicKey() *rsa.PublicKey {
	return j.publicKey
}

// KeyID returns the key ID from the JWTConfig.
//
// Returns:
//
//	string: The key ID.
func (j *TokenConfig) KeyID() string {
	return j.keyID
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

func (j *TokenConfig) Issuer() string {
	return j.issuer
}

func (j *TokenConfig) String() string {
	return fmt.Sprintf(
		"\tExpirationTime: %s\n"+
			"\tRefreshTokenDuration: %s\n"+
			"\tAccessTokenDuration: %s\n",
		j.expirationTime,
		j.refreshTokenDuration,
		j.accessTokenDuration,
	)
}

func defaultTokenConfig() *TokenConfig {
	privateKeyBase64 := os.Getenv(constants.TokenPrivateKeyENV)
	publicKeyBase64 := os.Getenv(constants.TokenPublicKeyENV)
	issuer := os.Getenv(constants.TokenIssuerENV)

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		panic("Failed to decode private key: " + err.Error())
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		panic("Failed to decode public key: " + err.Error())
	}

	privateKeyParsed, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		panic("Failed to parse private key: " + err.Error())
	}

	publicKeyParsed, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		panic("Failed to parse public key: " + err.Error())
	}

	return &TokenConfig{
		privateKey:           privateKeyParsed,
		publicKey:            publicKeyParsed,
		keyID:                crypto.GenerateJWKKeyID(publicKeyBase64),
		issuer:               issuer,
		expirationTime:       defaultExpirationTime,
		accessTokenDuration:  defaultAccessTokenDuration,
		refreshTokenDuration: defaultRefreshTokenDuration,
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
