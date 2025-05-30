package config

import (
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

const oneDay time.Duration = 24 * time.Hour

type TokenConfigYAML struct {
	SecretKey            *string `yaml:"secret_key,omitempty"`
	ExpirationTime       *int64  `yaml:"expiration_time,omitempty"`
	AccessTokenDuration  *int64  `yaml:"access_token_duration,omitempty"`
	RefreshTokenDuration *int64  `yaml:"refresh_token_duration,omitempty"`
}

func (tc *TokenConfigYAML) ToOptions() []config.TokenConfigOptions {
	options := []config.TokenConfigOptions{}

	if tc.ExpirationTime != nil {
		duration := time.Duration(*tc.ExpirationTime) * time.Minute
		options = append(options, config.WithExpirationTime(duration))
	}

	if tc.AccessTokenDuration != nil {
		duration := time.Duration(*tc.AccessTokenDuration) * time.Minute
		options = append(options, config.WithAccessTokenDuration(duration))
	}

	if tc.RefreshTokenDuration != nil {
		duration := time.Duration(*tc.RefreshTokenDuration) * (oneDay)
		options = append(options, config.WithRefreshTokenDuration(duration))
	}

	return options
}
