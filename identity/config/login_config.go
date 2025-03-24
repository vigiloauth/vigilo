package config

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/web"
)

// LoginConfig holds the configuration for login attempt throttling.
type LoginConfig struct {
	maxFailedAttempts int           // Maximum number of failed login attempts allowed.
	delay             time.Duration // Delay duration after exceeding max failed attempts.
	loginURL          string
}

// LoginConfigOptions is a function type used to configure LoginConfig options.
type LoginConfigOptions func(*LoginConfig)

const (
	defaultMaxFailedAttempts int           = 5                      // Default maximum number of failed login attempts.
	defaultDelay             time.Duration = 500 * time.Millisecond // Default delay duration (500 milliseconds).
)

// NewLoginConfig creates a new LoginConfig with default values and applies provided options.
//
// Parameters:
//
//	opts ...LoginConfigOptions: A variadic list of LoginConfigOptions functions to configure the LoginConfig.
//
// Returns:
//
//	*LoginConfig: A new LoginConfig instance.
func NewLoginConfig(opts ...LoginConfigOptions) *LoginConfig {
	lc := &LoginConfig{
		maxFailedAttempts: defaultMaxFailedAttempts,
		delay:             defaultDelay,
		loginURL:          web.UserEndpoints.Login,
	}

	for _, opt := range opts {
		opt(lc)
	}

	return lc
}

// WithMaxFailedAttempts configures the maximum number of failed login attempts for the LoginConfig.
//
// Parameters:
//
//	maxAttempts int: The maximum number of failed login attempts.
//
// Returns:
//
//	LoginConfigOptions: A function that configures the maximum failed attempts.
func WithMaxFailedAttempts(maxAttempts int) LoginConfigOptions {
	return func(lc *LoginConfig) {
		if maxAttempts > defaultMaxFailedAttempts {
			lc.maxFailedAttempts = maxAttempts
		}
	}
}

// WithDelay configures the delay duration for the LoginConfig.
//
// Parameters:
//
//	delay time.Duration: The delay duration.
//
// Returns:
//
//	LoginConfigOptions: A function that configures the delay duration.
func WithDelay(delay time.Duration) LoginConfigOptions {
	return func(lc *LoginConfig) {
		if delay > defaultDelay {
			lc.delay = delay
		}
	}
}

// MaxFailedAttempts returns the maximum number of failed login attempts from the LoginConfig.
//
// Returns:
//
//	int: The maximum number of failed login attempts.
func (lc *LoginConfig) MaxFailedAttempts() int {
	return lc.maxFailedAttempts
}

// WithLoginURL allows the user to define their own login URL.
//
// Parameters:
//
//	url string: The login url
//
// Returns:
//
// LoginConfigOptions: A function that configures the login url.
func WithLoginURL(url string) LoginConfigOptions {
	return func(lc *LoginConfig) {
		lc.loginURL = url
	}
}

// LoginURL returns the predefined login URL.
//
// Returns:
//
//	string: The predefined login URL.
func (lc *LoginConfig) LoginURL() string {
	return lc.loginURL
}

// Delay returns the delay duration from the LoginConfig.
//
// Returns:
//
//	time.Duration: The delay duration.
func (lc *LoginConfig) Delay() time.Duration {
	return lc.delay
}
