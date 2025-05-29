package config

import "github.com/vigiloauth/vigilo/v2/idp/config"

const TLSPort int = 587
const SSLPort int = 465

type SMTPConfigYAML struct {
	Host        *string `yaml:"host,omitempty"`
	Port        *int    `yaml:"port,omitempty"`
	Username    *string `yaml:"username,omitempty"`
	Password    *string `yaml:"password,omitempty"`
	FromAddress *string `yaml:"from_address,omitempty"`
	Encryption  *string `yaml:"encryption,omitempty"`
}

func (s *SMTPConfigYAML) ToOptions() []config.SMTPConfigOptions {
	options := []config.SMTPConfigOptions{}

	if s.Host != nil {
		options = append(options, config.WithSMTPHost(*s.Host))
	}

	if s.Port != nil {
		switch *s.Port {
		case TLSPort:
			options = append(options, config.WithTLS())
		case SSLPort:
			options = append(options, config.WithSSL())
		}
	}

	if s.Username != nil && s.Password != nil {
		options = append(options, config.WithCredentials(*s.Username, *s.Password))
	}

	if s.FromAddress != nil {
		options = append(options, config.WithFromAddress(*s.FromAddress))
	}

	if s.Encryption != nil {
		options = append(options, config.WithEncryption(*s.Encryption))
	}

	return options
}
