package config

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTConfig holds the configuration for generating JWT tokens.
type JWTConfig struct {
	Secret         string
	ExpirationTime time.Duration
	SigningMethod  jwt.SigningMethod
}

// LoginConfig holds configuration for user login.
type LoginConfig struct {
	MaxFailedAttempts int
	Delay             time.Duration
}

// ServerConfig holds configuration for the server.
type ServerConfig struct {
	Port         int
	CertFilePath *string
	KeyFilePath  *string
	ForceHTTPS   bool
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	JWTConfig    *JWTConfig
	LoginConfig  *LoginConfig
}

// NewServerConfig initializes and returns a ServerConfig instance with the provided settings.
func NewServerConfig(port int, certFilePath, keyFilePath *string, forceHTTPS bool, readTimeout, writeTimeout time.Duration, jwtConfig *JWTConfig, loginConfig *LoginConfig) *ServerConfig {
	return &ServerConfig{
		Port:         port,
		CertFilePath: certFilePath,
		KeyFilePath:  keyFilePath,
		ForceHTTPS:   forceHTTPS,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		JWTConfig:    jwtConfig,
		LoginConfig:  loginConfig,
	}
}

// NewDefaultServerConfig initializes and returns a ServerConfig instance with default settings.
// These defaults include a secure port (8443), optional HTTPS enforcement,
// read/write timeouts set to 15 seconds, and a default JWT configuration.
func NewDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:         8443,
		ForceHTTPS:   false,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		JWTConfig:    NewDefaultJWTConfig(),
		LoginConfig:  NewDefaultLoginConfig(),
	}
}

// NewJWTConfig initializes and returns a JWTConfig instance with the provided settings.
func NewCustomJWTConfig(secret string, expirationTime time.Duration, signingMethod jwt.SigningMethod) *JWTConfig {
	return &JWTConfig{
		Secret:         secret,
		ExpirationTime: expirationTime,
		SigningMethod:  signingMethod,
	}
}

// NewDefaultJWTConfig initializes and returns a JWTConfig instance with the default settings.
// These defaults include a secret key, expiration time of 15 minutes, and the HS256 signing method.
func NewDefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Secret:         "default_secret_key",
		ExpirationTime: 15 * time.Minute,
		SigningMethod:  jwt.SigningMethodHS256,
	}
}

// NewCustomLoginConfig initializes and returns a LoginConfig instance with the provided settings.
func NewCustomLoginConfig(maxFailedAttempts int, delay time.Duration) *LoginConfig {
	return &LoginConfig{
		MaxFailedAttempts: maxFailedAttempts,
	}
}

// NewDefaultLoginConfig initializes and returns a LoginConfig instance with the default settings.
// The default setting is 5 maximum failed login attempts.
func NewDefaultLoginConfig() *LoginConfig {
	return &LoginConfig{
		MaxFailedAttempts: 5,
		Delay:             500 * time.Millisecond,
	}
}
