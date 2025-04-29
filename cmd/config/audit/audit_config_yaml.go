package config

import (
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

type AuditLogConfigYAML struct {
	RetentionPeriod *int `yaml:"retention_period,omitempty"`
}

func (alc *AuditLogConfigYAML) ToOptions() []config.AuditLogConfigOptions {
	options := []config.AuditLogConfigOptions{}

	if alc.RetentionPeriod != nil {
		retention := time.Duration(*alc.RetentionPeriod) * 24 * time.Hour
		options = append(options, config.WithRetentionPeriod(retention))
	}

	return options
}
