package config

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
)

type LoginConfigYAML struct {
	MaxFailedAttempts *int    `yaml:"max_failed_attempts,omitempty"`
	Delay             *int64  `yaml:"delay,omitempty"`
	LoginURL          *string `yaml:"login_url,omitempty"`
}

func (lc *LoginConfigYAML) ToOptions() []config.LoginConfigOptions {
	options := []config.LoginConfigOptions{}

	if lc.MaxFailedAttempts != nil {
		options = append(options, config.WithMaxFailedAttempts(*lc.MaxFailedAttempts))
	}

	if lc.Delay != nil {
		delay := time.Duration(*lc.Delay) * time.Millisecond
		options = append(options, config.WithDelay(delay))
	}

	if lc.LoginURL != nil {
		options = append(options, config.WithLoginURL(*lc.LoginURL))
	}

	return options
}
