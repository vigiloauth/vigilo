package config

import (
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
)

type ServerConfigYAML struct {
	Port              *string `yaml:"port,omitempty"`
	CertFilePath      *string `yaml:"cert_file_path,omitempty"`
	KeyFilePath       *string `yaml:"key_file_path,omitempty"`
	SessionCookieName *string `yaml:"session_cookie_name,omitempty"`
	BaseURL           *string `yaml:"base_url,omitempty"`
	ForceHTTPS        *bool   `yaml:"force_https,omitempty"`

	ReadTimeout       *int64 `yaml:"read_timeout,omitempty"`
	WriteTimeout      *int64 `yaml:"write_timeout,omitempty"`
	AuthzCodeDuration *int64 `yaml:"authorization_code_duration,omitempty"`
}

func (sc *ServerConfigYAML) ToOptions() []config.ServerConfigOptions {
	options := []config.ServerConfigOptions{}

	if sc.Port != nil {
		options = append(options, config.WithPort(*sc.Port))
	}
	if sc.CertFilePath != nil {
		options = append(options, config.WithCertFilePath(*sc.CertFilePath))
	}
	if sc.KeyFilePath != nil {
		options = append(options, config.WithKeyFilePath(*sc.KeyFilePath))
	}
	if sc.SessionCookieName != nil {
		options = append(options, config.WithSessionCookieName(*sc.SessionCookieName))
	}
	if sc.BaseURL != nil {
		options = append(options, config.WithBaseURL(*sc.BaseURL))
	}
	if sc.ForceHTTPS != nil {
		options = append(options, config.WithForceHTTPS())
	}
	if sc.ReadTimeout != nil {
		timeoutDuration := time.Duration(*sc.ReadTimeout) * time.Second
		options = append(options, config.WithReadTimeout(timeoutDuration))
	}
	if sc.WriteTimeout != nil {
		timeoutDuration := time.Duration(*sc.WriteTimeout) * time.Second
		options = append(options, config.WithWriteTimeout(timeoutDuration))
	}
	if sc.AuthzCodeDuration != nil {
		duration := time.Duration(*sc.AuthzCodeDuration) * time.Minute
		options = append(options, config.WithAuthorizationCodeDuration(duration))
	}

	return options
}
