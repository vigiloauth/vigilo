package config

import "time"

// ServerConfig holds configuration for the server.
type ServerConfig struct {
	Port         int
	CertFilePath *string
	KeyFilePath  *string
	ForceHTTPS   bool
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewServerConfig initializes and returns a ServerConfig instance with the provided settings.
func NewServerConfig(port int, certFilePath, keyFilePath *string, forceHTTPS bool, readTimeout, writeTimeout time.Duration) *ServerConfig {
	return &ServerConfig{
		Port:         port,
		CertFilePath: certFilePath,
		KeyFilePath:  keyFilePath,
		ForceHTTPS:   forceHTTPS,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}
}

// NewDefaultServerConfig initializes and returns a ServerConfig instance with default settings.
// These defaults include a secure port (8443), optional HTTPS enforcement,
// and read/write timeouts set to 15 seconds.
// The returned configuration can be modified as needed.
func NewDefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Port:         8443,
		ForceHTTPS:   false,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
}
