package config

import (
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/internal/web"
)

// LoginConfig holds the configuration for login attempt throttling.
type LoginConfig struct {
	maxFailedAttempts int           // Maximum number of failed login attempts allowed.
	delay             time.Duration // Delay duration after exceeding max failed attempts in milliseconds
	loginURL          string
	logger            *Logger
	module            string
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
		logger:            GetLogger(),
		module:            "LoginConfig",
	}

	if len(opts) > 0 {
		lc.logger.Info(lc.module, "Creating login config with %d options", len(opts))
		for _, opt := range opts {
			opt(lc)
		}
	} else {
		lc.logger.Info(lc.module, "Using default login config")
	}

	lc.logger.Debug(lc.module, "\n\nLogin config parameters: %s", lc.String())
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
			lc.logger.Info(lc.module, "Configuring LoginConfig to use [%d] max failed login attempts", maxAttempts)
			lc.maxFailedAttempts = maxAttempts
		}
	}
}

// WithDelay configures the delay duration, in milliseconds for the LoginConfig.
// Default is 500 milliseconds
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
		if !isInMilliseconds(delay) {
			lc.logger.Warn(lc.module, "Delay duration is not in milliseconds, using default value of 500ms")
			lc.delay = defaultDelay
			return
		}
		lc.logger.Info(lc.module, "Configuring LoginConfig to use delay=[%s]", delay)
		lc.delay = delay
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
		lc.logger.Info(lc.module, "Configuring LoginConfig to use URL=[%s]", url)
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

func (lc *LoginConfig) String() string {
	return fmt.Sprintf(
		"\n\tMaxFailedAttempts: %d\n"+
			"\tDelay: %s\n"+
			"\tLoginURL: %s\n",
		lc.maxFailedAttempts,
		lc.delay,
		lc.loginURL,
	)
}
