package config

import "time"

type LoginConfig struct {
	maxFailedAttempts int
	delay             time.Duration
}

type LoginConfigOptions func(*LoginConfig)

const (
	defaultMaxFailedAttempts int           = 5
	defaultDelay             time.Duration = 500 * time.Millisecond
)

func NewLoginConfig(opts ...LoginConfigOptions) *LoginConfig {
	lc := &LoginConfig{
		maxFailedAttempts: defaultMaxFailedAttempts,
		delay:             defaultDelay,
	}

	for _, opt := range opts {
		opt(lc)
	}

	return lc
}

func WithMaxFailedAttempts(maxAttempts int) LoginConfigOptions {
	return func(lc *LoginConfig) {
		if maxAttempts > defaultMaxFailedAttempts {
			lc.maxFailedAttempts = maxAttempts
		}
	}
}

func WithDelay(delay time.Duration) LoginConfigOptions {
	return func(lc *LoginConfig) {
		if delay > defaultDelay {
			lc.delay = delay
		}
	}
}

func (lc *LoginConfig) MaxFailedAttempts() int {
	return lc.maxFailedAttempts
}

func (lc *LoginConfig) Delay() time.Duration {
	return lc.delay
}
