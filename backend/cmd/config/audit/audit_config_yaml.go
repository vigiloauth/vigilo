package config

import (
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

const oneDay time.Duration = 24 * time.Hour

type AuditLogConfigYAML struct {
	RetentionPeriod *int `yaml:"retention_period,omitempty"`
}

func (alc *AuditLogConfigYAML) ToOptions() []config.AuditLogConfigOptions {
	options := []config.AuditLogConfigOptions{}

	if alc.RetentionPeriod != nil {
		retention := time.Duration(*alc.RetentionPeriod) * oneDay
		options = append(options, config.WithRetentionPeriod(retention))
	}

	return options
}
