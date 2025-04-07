package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	login "github.com/vigiloauth/vigilo/cmd/config/login"
	password "github.com/vigiloauth/vigilo/cmd/config/password"
	server "github.com/vigiloauth/vigilo/cmd/config/server"
	token "github.com/vigiloauth/vigilo/cmd/config/token"
	"github.com/vigiloauth/vigilo/identity/config"
)

const testConfigFile string = "test-config.yaml"

func TestApplicationConfig_LoadConfigurations(t *testing.T) {
	appConfig := LoadConfigurations(testConfigFile)

	assert.NotNil(t, appConfig)
	assertServerConfig(appConfig.ServerConfig, t)
	assertTokenConfig(appConfig.TokenConfig, t)
	assertPasswordConfig(appConfig.PasswordConfig, t)
	assertLoginConfig(appConfig.LoginConfig, t)
}

func assertServerConfig(cfg server.ServerConfigYAML, t *testing.T) {
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.Port)
	assert.NotNil(t, cfg.CertFilePath)
	assert.NotNil(t, cfg.KeyFilePath)
	assert.NotNil(t, cfg.SessionCookieName)
	assert.NotNil(t, cfg.BaseURL)
	assert.NotNil(t, cfg.ForceHTTPS)
	assert.NotNil(t, cfg.ReadTimeout)
	assert.NotNil(t, cfg.WriteTimeout)
	assert.NotNil(t, cfg.AuthzCodeDuration)

	serverConfig := config.GetServerConfig()
	assert.NotNil(t, serverConfig)
	assert.Equal(t, *cfg.Port, serverConfig.Port())
	assert.Equal(t, *cfg.CertFilePath, serverConfig.CertFilePath())
	assert.Equal(t, *cfg.KeyFilePath, serverConfig.KeyFilePath())
	assert.Equal(t, *cfg.SessionCookieName, serverConfig.SessionCookieName())
	assert.Equal(t, *cfg.BaseURL, serverConfig.BaseURL())
	assert.Equal(t, *cfg.ForceHTTPS, serverConfig.ForceHTTPS())

	readTimeout := time.Duration(*cfg.ReadTimeout) * time.Second
	assert.Equal(t, readTimeout, serverConfig.ReadTimeout())

	writeTimeout := time.Duration(*cfg.WriteTimeout) * time.Second
	assert.Equal(t, writeTimeout, serverConfig.WriteTimeout())

	codeDuration := time.Duration(*cfg.AuthzCodeDuration) * time.Minute
	assert.Equal(t, codeDuration, serverConfig.AuthorizationCodeDuration())
}

func assertTokenConfig(cfg token.TokenConfigYAML, t *testing.T) {
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.SecretKey)
	assert.NotNil(t, cfg.ExpirationTime)
	assert.NotNil(t, cfg.AccessTokenDuration)
	assert.NotNil(t, cfg.RefreshTokenDuration)

	tokenConfig := config.GetServerConfig().TokenConfig()
	assert.NotNil(t, tokenConfig)
	assert.Equal(t, *cfg.SecretKey, tokenConfig.SecretKey())

	expirationTime := time.Duration(*cfg.ExpirationTime) * time.Minute
	assert.Equal(t, expirationTime, tokenConfig.ExpirationTime())

	accessTokenDuration := time.Duration(*cfg.AccessTokenDuration) * time.Minute
	assert.Equal(t, accessTokenDuration, tokenConfig.AccessTokenDuration())

	refreshTokenDuration := time.Duration(*cfg.RefreshTokenDuration) * (24 * time.Hour)
	assert.Equal(t, refreshTokenDuration, tokenConfig.RefreshTokenDuration())
}

func assertPasswordConfig(cfg password.PasswordConfigYAML, t *testing.T) {
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.RequireNumber)
	assert.NotNil(t, cfg.RequireSymbol)
	assert.NotNil(t, cfg.RequireUppercase)
	assert.NotNil(t, cfg.MinimumLength)

	passwordConfig := config.GetServerConfig().PasswordConfig()
	assert.NotNil(t, passwordConfig)
	assert.Equal(t, *cfg.RequireNumber, passwordConfig.RequireNumber())
	assert.Equal(t, *cfg.RequireSymbol, passwordConfig.RequireSymbol())
	assert.Equal(t, *cfg.RequireUppercase, passwordConfig.RequireUppercase())
	assert.Equal(t, *cfg.MinimumLength, passwordConfig.MinLength())
}

func assertLoginConfig(cfg login.LoginConfigYAML, t *testing.T) {
	assert.NotNil(t, cfg)
	assert.NotNil(t, cfg.MaxFailedAttempts)
	assert.NotNil(t, cfg.Delay)

	loginConfig := config.GetServerConfig().LoginConfig()
	assert.NotNil(t, loginConfig)
	assert.Equal(t, *cfg.MaxFailedAttempts, loginConfig.MaxFailedAttempts())

	delay := time.Duration(*cfg.Delay) * time.Millisecond
	assert.Equal(t, delay, loginConfig.Delay())
}
