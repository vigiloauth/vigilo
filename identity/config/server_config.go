package config

import (
	"fmt"
	"sync"
	"time"
)

type ServerConfig struct {
	port              int
	certFilePath      string
	keyFilePath       string
	forceHTTPS        bool
	readTimeout       time.Duration
	writeTimeout      time.Duration
	jwtConfig         *JWTConfig
	loginConfig       *LoginConfig
	smtpConfig        *SMTPConfig
	passwordConfig    *PasswordConfig
	requestsPerMinute int
}

type ServerConfigOptions func(*ServerConfig)

var (
	serverConfigInstance *ServerConfig
	serverConfigOnce     sync.Once
)

const (
	defaultPort              int           = 8443
	defaultHTTPSRequirement  bool          = false
	defaultReadTimeout       time.Duration = 15 * time.Second
	defaultWriteTimeout      time.Duration = 15 * time.Second
	defaultRequestsPerMinute int           = 100
)

// GetServerConfig returns the global server configuration
func GetServerConfig() *ServerConfig {
	if serverConfigInstance == nil {
		serverConfigOnce.Do(func() {
			serverConfigInstance = NewServerConfig()
		})
	}
	return serverConfigInstance
}

func NewServerConfig(opts ...ServerConfigOptions) *ServerConfig {
	sc := &ServerConfig{
		port:              defaultPort,
		forceHTTPS:        defaultHTTPSRequirement,
		readTimeout:       defaultReadTimeout,
		writeTimeout:      defaultWriteTimeout,
		jwtConfig:         NewJWTConfig(),
		loginConfig:       NewLoginConfig(),
		passwordConfig:    NewPasswordConfig(),
		requestsPerMinute: defaultRequestsPerMinute,
	}

	for _, opt := range opts {
		opt(sc)
	}

	serverConfigInstance = sc
	return sc
}

func WithPort(port int) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.port = port
	}
}

func WithCertFilePath(filePath string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.certFilePath = filePath
	}
}

func WithKeyFilePath(filePath string) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.keyFilePath = filePath
	}
}

func WithForceHTTPS() ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.forceHTTPS = true
	}
}

func WithReadTimeout(timeout time.Duration) ServerConfigOptions {
	return func(sc *ServerConfig) {
		if timeout > sc.readTimeout {
			sc.readTimeout = timeout
		}
	}
}

func WithWriteTimeout(timeout time.Duration) ServerConfigOptions {
	return func(sc *ServerConfig) {
		if timeout > sc.writeTimeout {
			sc.writeTimeout = timeout
		}
	}
}

func WithJWTConfig(jwtConfig *JWTConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.jwtConfig = jwtConfig
	}
}

func WithLoginConfig(loginConfig *LoginConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.loginConfig = loginConfig
	}
}

func WithSMTPConfig(smtpConfig *SMTPConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.smtpConfig = smtpConfig
	}
}

func WithPasswordConfig(passwordConfig *PasswordConfig) ServerConfigOptions {
	return func(sc *ServerConfig) {
		sc.passwordConfig = passwordConfig
	}
}

func WithMaxRequestsPerMinute(requests int) ServerConfigOptions {
	return func(sc *ServerConfig) {
		if requests > defaultRequestsPerMinute {
			sc.requestsPerMinute = requests
		}
	}
}

func (sc *ServerConfig) Port() int {
	return sc.port
}

func (sc *ServerConfig) CertFilePath() string {
	return sc.certFilePath
}

func (sc *ServerConfig) KeyFilePath() string {
	return sc.keyFilePath
}

func (sc *ServerConfig) ForceHTTPS() bool {
	return sc.forceHTTPS
}

func (sc *ServerConfig) ReadTimeout() time.Duration {
	return sc.readTimeout
}

func (sc *ServerConfig) WriteTimeout() time.Duration {
	return sc.writeTimeout
}

func (sc *ServerConfig) JWTConfig() *JWTConfig {
	return sc.jwtConfig
}

func (sc *ServerConfig) LoginConfig() *LoginConfig {
	return sc.loginConfig
}

func (sc *ServerConfig) SMTPConfig() *SMTPConfig {
	if sc.smtpConfig == nil {
		fmt.Println("Warning: SMTP configuration is not set")
		return nil
	}
	return sc.smtpConfig
}

func (sc *ServerConfig) PasswordConfig() *PasswordConfig {
	return sc.passwordConfig
}

func (sc *ServerConfig) MaxRequestsPerMinute() int {
	return sc.requestsPerMinute
}
