package config

import (
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

type ServerConfigYAML struct {
	Port                 *string `yaml:"port,omitempty"`
	CertFilePath         *string `yaml:"cert_file_path,omitempty"`
	KeyFilePath          *string `yaml:"key_file_path,omitempty"`
	SessionCookieName    *string `yaml:"session_cookie_name,omitempty"`
	ForceHTTPS           *bool   `yaml:"force_https,omitempty"`
	Domain               *string `yaml:"domain,omitempty"`
	EnableRequestLogging *bool   `yaml:"enable_request_logging,omitempty"`

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
	if sc.ForceHTTPS != nil {
		options = append(options, config.WithForceHTTPS())
	}
	if sc.EnableRequestLogging != nil {
		options = append(options, config.WithRequestLogging(*sc.EnableRequestLogging))
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
	if sc.Domain != nil {
		options = append(options, config.WithDomain(*sc.Domain))
	}

	return options
}
