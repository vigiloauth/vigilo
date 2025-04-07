package config

import "github.com/vigiloauth/vigilo/identity/config"

type PasswordConfigYAML struct {
	RequireUppercase *bool `yaml:"require_uppercase,omitempty"`
	RequireNumber    *bool `yaml:"require_number,omitempty"`
	RequireSymbol    *bool `yaml:"require_symbol,omitempty"`
	MinimumLength    *int  `yaml:"minimum_length,omitempty"`
}

func (pc *PasswordConfigYAML) ToOptions() []config.PasswordConfigOption {
	options := []config.PasswordConfigOption{}

	if pc.RequireUppercase != nil {
		options = append(options, config.WithUppercase())
	}

	if pc.RequireNumber != nil {
		options = append(options, config.WithNumber())
	}

	if pc.RequireSymbol != nil {
		options = append(options, config.WithSymbol())
	}

	if pc.MinimumLength != nil {
		options = append(options, config.WithMinLength(*pc.MinimumLength))
	}

	return options
}
