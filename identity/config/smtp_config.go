package config

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// SMTPConfig holds the configuration for SMTP email sending.
// SMTPConfig holds the configuration for SMTP email sending.
type SMTPConfig struct {
	server       string           // SMTP server address.
	port         int              // SMTP server port.
	encryption   EncryptionType   // Encryption type (none, starttls, tls).
	fromAddress  string           // Sender's email address.
	fromName     string           // Sender's name.
	replyTo      string           // Reply-to email address.
	templatePath string           // Path to email template.
	credentials  *SMTPCredentials // SMTP credentials (username, password).
	maxRetries   int              // Maximum number of retry attempts.
	retryDelay   time.Duration    // Delay between retry attempts.
	logger       *Logger
	module       string
}

// SMTPCredentials holds the username and password for SMTP authentication.
type SMTPCredentials struct {
	username string // SMTP username.
	password string // SMTP password.
}

// EncryptionType represents the encryption type for SMTP connections.
type EncryptionType string

const (
	None              EncryptionType = "none"               // No encryption.
	StartTLS          EncryptionType = "starttls"           // StartTLS encryption.
	TLS               EncryptionType = "tls"                // TLS encryption.
	DefaultTTL        time.Duration  = 24 * time.Hour       // Default time-to-live.
	gmailServer       string         = "smtp.gmail.com"     // Gmail SMTP server.
	outlookServer     string         = "smtp.office365.com" // Outlook SMTP server.
	DefaultSMTPPort   int            = 587                  // Default SMTP port.
	defaultSESRegion  string         = "us-east-1"          // Default Amazon SES region.
	defaultMaxRetries int            = 5                    // Default maximum retry attempts.
	defaultRetryDelay time.Duration  = 5 * time.Minute      // Default retry delay.
)

// NewSMTPConfig creates a new SMTPConfig instance.
//
// Parameters:
//
//	server, port, fromAddress, fromName, replyTo, templatePath: SMTP configuration parameters.
//	encryption: Encryption type.
//	credentials: SMTP credentials.
//
// Returns:
//
//	*SMTPConfig: A new SMTPConfig instance.
//	error: An error if the configuration is invalid.
func NewSMTPConfig(
	server string,
	port int,
	fromAddress string,
	fromName string,
	replyTo string,
	templatePath string,
	encryption EncryptionType,
	credentials *SMTPCredentials,
) (*SMTPConfig, error) {
	sc := &SMTPConfig{
		server:       server,
		port:         port,
		encryption:   encryption,
		fromAddress:  fromAddress,
		fromName:     fromName,
		replyTo:      replyTo,
		templatePath: templatePath,
		maxRetries:   defaultMaxRetries,
		retryDelay:   defaultRetryDelay,
		logger:       GetLogger(),
		module:       "SMTPConfig",
	}

	if credentials != nil {
		sc.credentials = credentials
	}

	if err := sc.validateSMTPConfiguration(); err != nil {
		sc.logger.Error(sc.module, "Failed to validate SMTP configuration: %v", err)
		return nil, err
	}

	sc.logger.Debug(sc.module, "\n\nUsing SMTPConfig: %s", sc.String())
	return sc, nil
}

// NewSMTPCredentials creates new SMTPCredentials instance.
//
// Parameters:
//
//	username, password: SMTP credentials.
//
// Returns:
//
//	*SMTPCredentials: A new SMTPCredentials instance.
//	error: An error if the credentials are invalid.
func NewSMTPCredentials(username, password string) (*SMTPCredentials, error) {
	creds := &SMTPCredentials{
		username: username,
		password: password,
	}

	if err := creds.validateSMTPCredentials(); err != nil {
		return nil, err
	}

	return creds, nil
}

// DefaultGmailConfig creates a default SMTPConfig for Gmail.
//
// Parameters:
//
//	fromAddress, fromName: Sender's email address and name.
//
// Returns:
//
//	*SMTPConfig: A new SMTPConfig instance for Gmail.
//	error: An error if the configuration is invalid.
func DefaultGmailConfig(fromAddress, fromName string) (*SMTPConfig, error) {
	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	return NewSMTPConfig(gmailServer, DefaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

// DefaultOutlookConfig creates a default SMTPConfig for Outlook.
//
// Parameters:
//
//	fromAddress, fromName: Sender's email address and name.
//
// Returns:
//
//	*SMTPConfig: A new SMTPConfig instance for Outlook.
//	error: An error if the configuration is invalid.
func DefaultOutlookConfig(fromAddress, fromName string) (*SMTPConfig, error) {
	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	return NewSMTPConfig(outlookServer, DefaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

// DefaultAmazonSESConfig creates a default SMTPConfig for Amazon SES.
//
// Parameters:
//
//	region, fromAddress, fromName: Amazon SES region, sender's email address and name.
//
// Returns:
//
//	*SMTPConfig: A new SMTPConfig instance for Amazon SES.
//	error: An error if the configuration is invalid.
func DefaultAmazonSESConfig(region, fromAddress, fromName string) (*SMTPConfig, error) {
	if region == "" {
		region = defaultSESRegion
	}

	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	server := fmt.Sprintf("email-smtp.%s.amazonaws.com", region)
	return NewSMTPConfig(server, DefaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

// Server returns the SMTP server address.
func (sc *SMTPConfig) Server() string {
	return sc.server
}

// SetServer sets the SMTP server address.
func (sc *SMTPConfig) SetServer(server string) {
	sc.server = server
}

// Port returns the SMTP server port.
func (sc *SMTPConfig) Port() int {
	return sc.port
}

// SetPort sets the SMTP server port.
func (sc *SMTPConfig) SetPort(port int) {
	sc.port = port
}

// Encryption returns the encryption type.
func (sc *SMTPConfig) Encryption() EncryptionType {
	return sc.encryption
}

// SetEncryption sets the encryption type.
func (sc *SMTPConfig) SetEncryption(encryption EncryptionType) {
	sc.encryption = encryption
}

// FromAddress returns the sender's email address.
func (sc *SMTPConfig) FromAddress() string {
	return sc.fromAddress
}

// SetFromAddress sets the sender's email address.
func (sc *SMTPConfig) SetFromAddress(address string) {
	sc.fromAddress = address
}

// FromName returns the sender's name.
func (sc *SMTPConfig) FromName() string {
	return sc.fromName
}

// SetFromName sets the sender's name
func (sc *SMTPConfig) SetFromName(fromName string) {
	sc.fromName = fromName
}

// ReplyTo returns the reply-to email address.
func (sc *SMTPConfig) ReplyTo() string {
	return sc.replyTo
}

// SetReplyTo sets the reply-to email address.
//
// Returns:
//
//	error: An error if the reply to email is invalid.
func (c *SMTPConfig) SetReplyTo(replyTo string) error {
	if err := validateEmail(replyTo); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidFormat, "invalid `reply-to`")
	}

	c.replyTo = replyTo
	return nil
}

// TemplatePath returns the path to the email template.
func (sc *SMTPConfig) TemplatePath() string {
	return sc.templatePath
}

// SetTemplatePath sets the path to the email template.
//
// Returns:
//
//	error: An error if the template path is empty.
func (sc *SMTPConfig) SetTemplatePath(templatePath string) error {
	if templatePath == "" {
		return errors.New(errors.ErrCodeEmptyInput, "'template path' cannot be empty")
	}

	sc.templatePath = templatePath
	return nil
}

// HasCredentials returns true if SMTP credentials are set.
func (sc *SMTPConfig) HasCredentials() bool {
	return sc.credentials != nil &&
		sc.credentials.username != "" &&
		sc.credentials.password != ""
}

// Credentials returns the SMTP credentials.
func (sc *SMTPConfig) Credentials() *SMTPCredentials {
	return sc.credentials
}

// SetCredentials sets the SMTP credentials to be used during authorization.
// Parameters:
//
//	username, password
//
// Returns:
//
//	errors: An error creating the SMTP Credentials.
//	nil: If no errors occur.
func (sc *SMTPConfig) SetCredentials(username, password string) error {
	credentials, err := NewSMTPCredentials(username, password)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeValidationError, "error validating SMTP Credentials")
	}

	sc.credentials = credentials
	return nil
}

// MaxRetries returns the maximum number of retry attempts.
func (sc *SMTPConfig) MaxRetries() int {
	return sc.maxRetries
}

// SetMaxRetries sets the maximum number of retry attempts.
func (sc *SMTPConfig) SetMaxRetries(retries int) {
	if retries > sc.maxRetries {
		sc.maxRetries = retries
	}
}

// RetryDelay returns the delay between retry attempts.
func (sc *SMTPConfig) RetryDelay() time.Duration {
	return sc.retryDelay
}

// SetRetryDelay sets the delay between retry attempts.
func (sc *SMTPConfig) SetRetryDelay(delay time.Duration) {
	if delay > sc.retryDelay {
		sc.retryDelay = delay
	}
}

// Username returns the SMTP username.
func (c *SMTPCredentials) Username() string {
	return c.username
}

// Password returns the SMTP password.
func (c *SMTPCredentials) Password() string {
	return c.password
}

// validateSMTPConfiguration validates the SMTP configuration.
//
// Returns:
//
//	error: An error if the configuration is invalid.
func (sc *SMTPConfig) validateSMTPConfiguration() error {
	if sc.server == "" {
		return errors.New(errors.ErrCodeEmptyInput, "SMTP server cannot be empty")
	}

	if sc.port <= 0 || sc.port > 65535 {
		message := fmt.Sprintf("invalid port number: %d (must be between 1-65535)", sc.port)
		return errors.New(errors.ErrCodeInvalidFormat, message)
	}
	if !isValidEncryption(sc.encryption) {
		message := fmt.Sprintf("invalid encryption type: %s (must be none, starttls, or tls)", sc.encryption)
		return errors.New(errors.ErrCodeInvalidFormat, message)
	}
	if err := validateEmail(sc.fromAddress); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidFormat, "invalid `from address`")

	}
	if sc.replyTo != "" {
		if err := validateEmail(sc.replyTo); err != nil {
			return errors.Wrap(err, errors.ErrCodeInvalidFormat, "invalid `reply-to` address")
		}
	}

	return nil
}

// validateSMTPCredentials validates the SMTP credentials.
//
// Returns:
//
//	error: An error if the credentials are invalid.
func (c *SMTPCredentials) validateSMTPCredentials() error {
	if c.username == "" {
		return errors.New(errors.ErrCodeEmptyInput, "empty `username` field")
	}

	if c.password == "" {
		return errors.New(errors.ErrCodeEmptyInput, "empty `password` field")
	}

	return nil
}

// isValidEncryption checks if the encryption type is valid.
func isValidEncryption(et EncryptionType) bool {
	return et == None || et == StartTLS || et == TLS
}

// validateEmail validates an email address.
//
// Returns:
//
//	error: An error if the email address is invalid.
func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("email must contain '@' and '.'")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("email must contain exactly one '@'")
	}

	local, domain := parts[0], parts[1]
	if local == "" {
		return fmt.Errorf("local part of email cannot be empty")
	}

	if _, err := net.LookupMX(domain); err != nil {
		fmt.Printf("Warning: MX record lookup failed for domain %s: %v\n", domain, err)
	}

	return nil
}

// String returns a string representation of the SMTPConfig.
func (sc *SMTPConfig) String() string {
	return fmt.Sprintf(
		"\n\tServer: %s\n"+
			"\tPort: %d\n"+
			"\tEncryption: %s\n"+
			"\tFromAddress: %s\n"+
			"\tFromName: %s",
		sc.server,
		sc.port,
		sc.encryption,
		sc.fromAddress,
		sc.fromName,
	)
}

// String returns a string representation of the SMTPCredentials.
func (c *SMTPCredentials) String() string {
	return fmt.Sprintf("SMTPCredentials{username: %s, password: [REDACTED]}", c.username)
}
