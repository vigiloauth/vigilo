package config

import (
	err "errors"
	"fmt"
	"net"
	"strings"

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
}

type SMTPCredentials struct {
	username string
	password string
}

type EncryptionType string

const (
	None             EncryptionType = "none"
	StartTLS         EncryptionType = "starttls"
	TLS              EncryptionType = "tls"
	gmailServer      string         = "smtp.gmail.com"
	outlookServer    string         = "smtp.office365.com"
	defaultSMTPPort  int            = 587
	defaultSESRegion string         = "us-east-1"
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

	return NewSMTPConfig(gmailServer, defaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

func DefaultOutlookConfig(fromAddress, fromName string) (*SMTPConfig, error) {
	credentials := &SMTPCredentials{
		username: "",
		password: "",
	}

	return NewSMTPConfig(outlookServer, defaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
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
	return NewSMTPConfig(server, defaultSMTPPort, fromAddress, fromName, "", "", StartTLS, credentials)
}

func SetCredentials(config *SMTPConfig, username, password string) error {
	if config == nil {
		return errors.NewEmptyInputError("SMTP configuration")
	}

	credentials, err := NewSMTPCredentials(username, password)
	if err != nil {
		return err
	}

	config.credentials = credentials
	return nil
}

func SetReplyTo(config *SMTPConfig, replyTo string) error {
	if config == nil {
		return errors.NewEmptyInputError("SMTP configuration")
	}

	if err := validateEmail(replyTo); err != nil {
		return err
	}

	config.replyTo = replyTo
	return nil
}

func SetTemplatePath(config *SMTPConfig, templatePath string) error {
	if config == nil {
		return errors.NewEmptyInputError("SMTP configuration")
	}

	if templatePath == "" {
		return errors.NewEmptyInputError("template path")
	}

	config.templatePath = templatePath
	return nil
}

func (sc *SMTPConfig) Server() string {
	return sc.server
}

func (sc *SMTPConfig) Port() int {
	return sc.port
}

func (sc *SMTPConfig) Encryption() EncryptionType {
	return sc.encryption
}

func (sc *SMTPConfig) FromAddress() string {
	return sc.fromAddress
}

func (sc *SMTPConfig) FromName() string {
	return sc.fromName
}

func (sc *SMTPConfig) ReplyTo() string {
	return sc.replyTo
}

func (sc *SMTPConfig) TemplatePath() string {
	return sc.templatePath
}

func (sc *SMTPConfig) HasCredentials() bool {
	return sc.credentials != nil &&
		sc.credentials.username != "" &&
		sc.credentials.password != ""
}

func (sc *SMTPConfig) Credentials() *SMTPCredentials {
	return sc.credentials
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
