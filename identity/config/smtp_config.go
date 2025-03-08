package config

import (
	err "errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
)

type SMTPConfig struct {
	server       string
	port         int
	encryption   EncryptionType
	fromAddress  string
	fromName     string
	replyTo      string
	templatePath string
	credentials  *SMTPCredentials
	maxRetries   int
	retryDelay   time.Duration
}

type SMTPCredentials struct {
	username string
	password string
}

type EncryptionType string

const (
	None              EncryptionType = "none"
	StartTLS          EncryptionType = "starttls"
	TLS               EncryptionType = "tls"
	DefaultTTL        time.Duration  = 24 * time.Hour
	gmailServer       string         = "smtp.gmail.com"
	outlookServer     string         = "smtp.office365.com"
	DefaultSMTPPort   int            = 587
	defaultSESRegion  string         = "us-east-1"
	defaultMaxRetries int            = 5
	defaultRetryDelay time.Duration  = 5 * time.Minute
)

func NewSMTPConfig(server string, port int, fromAddress, fromName, replyTo, templatePath string, encryption EncryptionType, credentials *SMTPCredentials) (*SMTPConfig, error) {
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
	}

	if credentials != nil {
		sc.credentials = credentials
	}

	if err := sc.validateSMTPConfiguration(); err != nil {
		return nil, err
	}

	return sc, nil
}

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

func DefaultGmailConfig(fromAddress, fromName string) (*SMTPConfig, error) {
	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	return NewSMTPConfig(gmailServer, DefaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

func DefaultOutlookConfig(fromAddress, fromName string) (*SMTPConfig, error) {
	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	return NewSMTPConfig(outlookServer, DefaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

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

func (sc *SMTPConfig) Server() string {
	return sc.server
}

func (sc *SMTPConfig) SetServer(server string) {
	sc.server = server
}

func (sc *SMTPConfig) Port() int {
	return sc.port
}

func (sc *SMTPConfig) SetPort(port int) {
	sc.port = port
}

func (sc *SMTPConfig) Encryption() EncryptionType {
	return sc.encryption
}

func (sc *SMTPConfig) SetEncryption(encryption EncryptionType) {
	sc.encryption = encryption
}

func (sc *SMTPConfig) FromAddress() string {
	return sc.fromAddress
}

func (sc *SMTPConfig) SetFromAddress(address string) {
	sc.fromAddress = address
}

func (sc *SMTPConfig) FromName() string {
	return sc.fromName
}

func (sc *SMTPConfig) ReplyTo() string {
	return sc.replyTo
}

func (c *SMTPConfig) SetReplyTo(replyTo string) error {
	if err := validateEmail(replyTo); err != nil {
		return err
	}

	c.replyTo = replyTo
	return nil
}

func (sc *SMTPConfig) TemplatePath() string {
	return sc.templatePath
}

func (sc *SMTPConfig) SetTemplatePath(templatePath string) error {
	if templatePath == "" {
		return errors.NewEmptyInputError("template path")
	}

	sc.templatePath = templatePath
	return nil
}

func (sc *SMTPConfig) HasCredentials() bool {
	return sc.credentials != nil &&
		sc.credentials.username != "" &&
		sc.credentials.password != ""
}

func (sc *SMTPConfig) Credentials() *SMTPCredentials {
	return sc.credentials
}

func (sc *SMTPConfig) SetCredentials(username, password string) error {
	credentials, err := NewSMTPCredentials(username, password)
	if err != nil {
		return err
	}

	sc.credentials = credentials
	return nil
}

func (sc *SMTPConfig) MaxRetries() int {
	return sc.maxRetries
}

func (sc *SMTPConfig) SetMaxRetries(retries int) {
	if retries > sc.maxRetries {
		sc.maxRetries = retries
	}
}

func (sc *SMTPConfig) RetryDelay() time.Duration {
	return sc.retryDelay
}

func (sc *SMTPConfig) SetRetryDelay(delay time.Duration) {
	if delay > sc.retryDelay {
		sc.retryDelay = delay
	}
}

func (c *SMTPCredentials) Username() string {
	return c.username
}

func (c *SMTPCredentials) Password() string {
	return c.password
}

func (sc *SMTPConfig) validateSMTPConfiguration() error {
	if sc.server == "" {
		return errors.NewEmptyInputError("SMTP server")
	}

	if sc.port <= 0 || sc.port > 65535 {
		message := fmt.Sprintf("invalid port number: %d (must be between 1-65535)", sc.port)
		return errors.NewInvalidFormatError("port", message)
	}
	if !isValidEncryption(sc.encryption) {
		message := fmt.Sprintf("invalid encryption type: %s (must be none, starttls, or tls)", sc.encryption)
		return errors.NewInvalidFormatError("encryption type", message)
	}
	if err := validateEmail(sc.fromAddress); err != nil {
		return errors.NewInvalidFormatError("email", err.Error())
	}
	if sc.replyTo != "" {
		if err := validateEmail(sc.replyTo); err != nil {
			return fmt.Errorf("invalid reply-to address: %w", err)
		}
	}

	return nil
}

func (c *SMTPCredentials) validateSMTPCredentials() error {
	if c.username == "" {
		return errors.NewEmptyInputError("username")
	}

	if c.password == "" {
		return errors.NewEmptyInputError("password")
	}

	return nil
}

func isValidEncryption(et EncryptionType) bool {
	return et == None || et == StartTLS || et == TLS
}

func validateEmail(email string) error {
	if email == "" {
		return err.New("email cannot be empty")
	}

	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return err.New("email must contain '@' and '.'")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return err.New("email must contain exactly one '@'")
	}

	local, domain := parts[0], parts[1]
	if local == "" {
		return err.New("local part of email cannot be empty")
	}

	if _, err := net.LookupMX(domain); err != nil {
		fmt.Printf("Warning: MX record lookup failed for domain %s: %v\n", domain, err)
	}

	return nil
}

func (sc *SMTPConfig) String() string {
	return fmt.Sprintf("SMTPConfig{server: %s, port: %d, encryption: %s, fromAddress: %s, fromName: %s}",
		sc.server, sc.port, sc.encryption, sc.fromAddress, sc.fromName)
}

func (c *SMTPCredentials) String() string {
	return fmt.Sprintf("SMTPCredentials{username: %s, password: [REDACTED]}", c.username)
}
