package config

import "time"

// AuditLogConfig holds configuration settings for audit logging,
// such as how long to retain audit logs.
type AuditLogConfig struct {
	retentionPeriod time.Duration
}

// AuditLogConfigOptions defines a function signature for modifying AuditLogConfig.
type AuditLogConfigOptions func(*AuditLogConfig)

// Default retention period for audit logs: 90 days.
const defaultRetentionPeriod time.Duration = 90 * 24 * time.Hour

// NewAuditLogConfig creates a new AuditLogConfig instance,
// applying any provided options to override the default values.
func NewAuditLogConfig(opts ...AuditLogConfigOptions) *AuditLogConfig {
	cfg := &AuditLogConfig{retentionPeriod: defaultRetentionPeriod}
	for _, opt := range opts {
		opt(cfg)
	}
	return cfg
}

// WithRetentionPeriod returns an option that sets a custom retention period
// for audit logs. Use this with NewAuditLogConfig to override the default.
func WithRetentionPeriod(retentionPeriod time.Duration) AuditLogConfigOptions {
	return func(alc *AuditLogConfig) {
		alc.retentionPeriod = retentionPeriod
	}
}

// RetentionPeriod returns the configured audit log retention period.
func (alc *AuditLogConfig) RetentionPeriod() time.Duration {
	return alc.retentionPeriod
}
