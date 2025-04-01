package config

import (
	"fmt"
	"sync"
	"time"
)

// ServerConfig holds the configuration for the server.
type ServerConfig struct {
	certFilePath      string // Path to the SSL certificate file.
	keyFilePath       string // Path to the SSL key file.
	baseURL           string // Base URL of the server.
	sessionCookieName string // Name of the session cookie.

	forceHTTPS        bool // Whether to force HTTPS connections.
	port              int  // Port number the server listens on.
	requestsPerMinute int  // Maximum requests allowed per minute.

	readTimeout  time.Duration // Read timeout for HTTP requests.
	writeTimeout time.Duration // Write timeout for HTTP responses.

	tokenConfig    *TokenConfig    // JWT configuration.
	loginConfig    *LoginConfig    // Login configuration.
	smtpConfig     *SMTPConfig     // SMTP configuration.
	passwordConfig *PasswordConfig // Password configuration.
	logger         *Logger         // Logging Configuration
}

// ServerConfigOptions is a function type used to configure ServerConfig options.
type ServerConfigOptions func(*ServerConfig)

var (
	serverConfigInstance *ServerConfig // Singleton instance of ServerConfig.
	serverConfigOnce     sync.Once     // Ensures singleton initialization.
)

const (
	defaultPort              int           = 8443                         // Default port number.
	defaultHTTPSRequirement  bool          = false                        // Default HTTPS requirement.
	defaultReadTimeout       time.Duration = 15 * time.Second             // Default read timeout.
	defaultWriteTimeout      time.Duration = 15 * time.Second             // Default write timeout.
	defaultRequestsPerMinute int           = 100                          // Default maximum requests per minute.
	defaultSessionCookieName string        = "vigilo-auth-session-cookie" // Default session cookie name.
)

// GetServerConfig returns the global server configuration instance (singleton).
//
// Returns:
//
//	*ServerConfig: The server configuration instance.
func GetServerConfig() *ServerConfig {
	if serverConfigInstance == nil {
		serverConfigOnce.Do(func() {
			serverConfigInstance = NewServerConfig()
		})
	}
	return serverConfigInstance
}

// NewServerConfig creates a new ServerConfig with default values and applies provided options.
//
// Parameters:
//
//	opts ...ServerConfigOptions: A variadic list of ServerConfigOptions functions to configure the ServerConfig.
//
// Returns:
//
//	*ServerConfig: A new ServerConfig instance.
func NewServerConfig(opts ...ServerConfigOptions) *ServerConfig {
	sc := &ServerConfig{
		port:              defaultPort,
		forceHTTPS:        defaultHTTPSRequirement,
		readTimeout:       defaultReadTimeout,
		writeTimeout:      defaultWriteTimeout,
		tokenConfig:       NewTokenConfig(),
		loginConfig:       NewLoginConfig(),
		passwordConfig:    NewPasswordConfig(),
		requestsPerMinute: defaultRequestsPerMinute,
		sessionCookieName: defaultSessionCookieName,
		logger:            GetLogger(),
	}

	for _, opt := range opts {
		opt(sc)
	}

	serverConfigInstance = sc // Set the singleton instance.
	return sc
}

// WithPort configures the server port.
//
// Parameters:
//
//	port int: The port number.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the port.
func WithPort(port int) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.port = port
	}
}

// WithCertFilePath configures the SSL certificate file path.
//
// Parameters:
//
//	filePath string: The certificate file path.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the certificate file path.
func WithCertFilePath(filePath string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.certFilePath = filePath
	}
}

// WithKeyFilePath configures the SSL key file path.
//
// Parameters:
//
//	filePath string: The key file path.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the key file path.
func WithKeyFilePath(filePath string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.keyFilePath = filePath
	}
}

// WithSessionCookieName configures the session cookie name.
//
// Parameters:
//
//	cookieName string: The session cookie name.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the session cookie name.
func WithSessionCookieName(cookieName string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.sessionCookieName = cookieName
	}
}

// WithBaseURL configures the server base URL.
//
// Parameters:
//
//	baseURL string: The base URL.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the base URL.
func WithBaseURL(baseURL string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.baseURL = baseURL
	}
}

// WithForceHTTPS configures whether to force HTTPS connections.
//
// Returns:
//
//	ServerConfigOptions: A function that configures HTTPS forcing.
func WithForceHTTPS() ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.forceHTTPS = true
	}
}

// WithReadTimeout configures the read timeout.
//
// Parameters:
//
//	timeout time.Duration: The read timeout duration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the read timeout.
func WithReadTimeout(timeout time.Duration) ServerConfigOptions {
	return func(sc *ServerConfig) {
		if timeout > sc.readTimeout {
			sc.readTimeout = timeout
		}
	}
}

// WithWriteTimeout configures the write timeout.
//
// Parameters:
//
//	timeout time.Duration: The write timeout duration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the write timeout.
func WithWriteTimeout(timeout time.Duration) ServerConfigOptions {
	return func(sc *ServerConfig) {
		if timeout > sc.writeTimeout {
			sc.writeTimeout = timeout
		}
	}
}

// WithTokenConfig configures the JWT configuration.
//
// Parameters:
//
//	jwtConfig *JWTConfig: The JWT configuration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the JWT configuration.
func WithTokenConfig(jwtConfig *TokenConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.tokenConfig = jwtConfig
	}
}

// WithLoginConfig configures the login configuration.
//
// Parameters:
//
//	loginConfig *LoginConfig: The login configuration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the login configuration.
func WithLoginConfig(loginConfig *LoginConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.loginConfig = loginConfig
	}
}

// WithSMTPConfig configures the SMTP configuration.
//
// Parameters:
//
//	smtpConfig *SMTPConfig: The SMTP configuration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the SMTP configuration.
func WithSMTPConfig(smtpConfig *SMTPConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.smtpConfig = smtpConfig
	}
}

// WithPasswordConfig configures the password configuration.
//
// Parameters:
//
//	passwordConfig *PasswordConfig: The password configuration.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the password configuration.
func WithPasswordConfig(passwordConfig *PasswordConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.passwordConfig = passwordConfig
	}
}

// WithMaxRequestsPerMinute configures the max requests the server can take per minute.
//
// Parameters:
//
//	requests int: The amount of requests.
//
// Returns:
//
//	ServerConfigOptions: A function that configures the server configuration.
func WithMaxRequestsPerMinute(requests int) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.requestsPerMinute = requests
	}
}

// Port returns the servers port from.
//
// Returns:
//
//	int: The port number.
func (sc *ServerConfig) Port() int {
	return sc.port
}

// BaseURL returns the servers base URL
//
// Returns:
//
//	string: The base URL
func (sc *ServerConfig) BaseURL() string {
	return sc.baseURL
}

// CertFilePath returns the servers cert file path.
//
// Returns:
//
//	string: The cert file path
func (sc *ServerConfig) CertFilePath() string {
	return sc.certFilePath
}

// KeyFilePath returns the path to the SSL key file.
//
// Returns:
//
//	string: The SSL key file path.
func (sc *ServerConfig) KeyFilePath() string {
	return sc.keyFilePath
}

// ForceHTTPS returns whether HTTPS connections are enforced.
//
// Returns:
//
//	bool: True if HTTPS is enforced, false otherwise.
func (sc *ServerConfig) ForceHTTPS() bool {
	return sc.forceHTTPS
}

// ReadTimeout returns the read timeout for HTTP requests.
//
// Returns:
//
//	time.Duration: The read timeout duration.
func (sc *ServerConfig) ReadTimeout() time.Duration {
	return sc.readTimeout
}

// WriteTimeout returns the write timeout for HTTP responses.
//
// Returns:
//
//	time.Duration: The write timeout duration.
func (sc *ServerConfig) WriteTimeout() time.Duration {
	return sc.writeTimeout
}

// TokenConfig returns the Token configuration.
//
// Returns:
//
//	*TokenConfig: The Token configuration.
func (sc *ServerConfig) TokenConfig() *TokenConfig {
	return sc.tokenConfig
}

// LoginConfig returns the login configuration.
//
// Returns:
//
//	*LoginConfig: The login configuration.
func (sc *ServerConfig) LoginConfig() *LoginConfig {
	return sc.loginConfig
}

// SMTPConfig returns the SMTP configuration.
//
// Returns:
//
//	*SMTPConfig: The SMTP configuration, or nil if not set.
//	Prints a warning to standard output if the configuration is not set.
func (sc *ServerConfig) SMTPConfig() *SMTPConfig {
	if sc.smtpConfig == nil {
		fmt.Println("Warning: SMTP configuration is not set")
		return nil
	}
	return sc.smtpConfig
}

// PasswordConfig returns the password configuration.
//
// Returns:
//
//	*PasswordConfig: The password configuration.
func (sc *ServerConfig) PasswordConfig() *PasswordConfig {
	return sc.passwordConfig
}

// SessionCookieName returns the name of the session cookie.
//
// Returns:
//
//	string: The session cookie name.
func (sc *ServerConfig) SessionCookieName() string {
	return sc.sessionCookieName
}

// MaxRequestsPerMinute returns the maximum number of requests allowed per minute.
//
// Returns:
//
//	int: The maximum number of requests per minute.
func (sc *ServerConfig) MaxRequestsPerMinute() int {
	return sc.requestsPerMinute
}

func (sc *ServerConfig) Logger() *Logger {
	return sc.logger
}
