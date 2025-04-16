package config

type SMTPConfig struct {
	host        string
	port        int
	username    string
	password    string
	fromAddress string
	encryption  string
	useAuth     bool
	isHealthy   bool

	logger *Logger
	module string
}

const (
	defaultSMTPHost    string = "smtp.gmail.com"
	TLSPort            int    = 587
	SSLPort            int    = 465
	defaultFromAddress string = "vigiloauth@gmail.com"
	defaultUseAuth     bool   = true
	defaultUsername    string = "vigiloauth@gmail.com"
	defaultPassword    string = "tpkk fdyd hmvp rgpn"

	SSLEncryption string = "ssl"
	TLSEncryption string = "tls"
)

type SMTPConfigOptions func(*SMTPConfig)

func NewSMTPConfig(opts ...SMTPConfigOptions) *SMTPConfig {
	cfg := defaultSMTPConfig()
	cfg.loadOptions(opts...)
	return cfg
}

func WithSMTPHost(host string) SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.logger.Info(s.module, "Configuring SMTP Config to use host [%s]", host)
		s.host = host
	}
}

func WithSSL() SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.port = SSLPort
	}
}

func WithTLS() SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.port = TLSPort
	}
}

func WithCredentials(username, password string) SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.username = username
		s.password = password
	}
}

func WithFromAddress(fromAddress string) SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.fromAddress = fromAddress
	}
}

func WithAuthentication() SMTPConfigOptions {
	return func(s *SMTPConfig) {
		s.useAuth = true
	}
}

func WithEncryption(encryption string) SMTPConfigOptions {
	return func(s *SMTPConfig) {
		if encryption != SSLEncryption && encryption != TLSEncryption {
			s.logger.Warn(s.module, "SMTP Configuration not using TLS or SSL, default to SSL")
			s.encryption = SSLEncryption
			return
		}
		s.encryption = encryption
	}
}

func (s *SMTPConfig) Host() string {
	return s.host
}

func (s *SMTPConfig) Port() int {
	return s.port
}

func (s *SMTPConfig) Username() string {
	return s.username
}

func (s *SMTPConfig) Password() string {
	return s.password
}

func (s *SMTPConfig) FromAddress() string {
	return s.fromAddress
}

func (s *SMTPConfig) UseAuth() bool {
	return s.useAuth
}

func (s *SMTPConfig) SetHealth(isHealthy bool) {
	s.isHealthy = isHealthy
}

func (s *SMTPConfig) IsHealthy() bool {
	return s.isHealthy
}

func (cfg *SMTPConfig) loadOptions(opts ...SMTPConfigOptions) {
	if len(opts) > 0 {
		cfg.logger.Info(cfg.module, "Creating SMTP configuration with %d options", len(opts))
		cfg.loadOptions(opts...)
	} else {
		cfg.logger.Info(cfg.module, "Using default SMTP configuration")
	}
}

func defaultSMTPConfig() *SMTPConfig {
	return &SMTPConfig{
		host:        defaultSMTPHost,
		port:        TLSPort,
		fromAddress: defaultFromAddress,
		useAuth:     defaultUseAuth,
		encryption:  TLSEncryption,
		logger:      GetLogger(),
		module:      "SMTP Config",
		username:    defaultUsername,
		password:    defaultPassword,
	}
}
