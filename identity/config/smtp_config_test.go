package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSMTPConfig(t *testing.T) {
	creds, err := NewSMTPCredentials("user", "pass")
	assert.NoError(t, err)

	config, err := NewSMTPConfig("smtp.example.com", 587, "from@example.com", "From Name", "replyto@example.com", "/path/to/template", StartTLS, creds)
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "smtp.example.com", config.Server())
	assert.Equal(t, 587, config.Port())
	assert.Equal(t, StartTLS, config.Encryption())
	assert.Equal(t, "from@example.com", config.FromAddress())
	assert.Equal(t, "From Name", config.FromName())
	assert.Equal(t, "replyto@example.com", config.ReplyTo())
	assert.Equal(t, "/path/to/template", config.TemplatePath())
	assert.True(t, config.HasCredentials())
	assert.Equal(t, creds, config.Credentials())
}

func TestNewSMTPCredentials(t *testing.T) {
	creds, err := NewSMTPCredentials("user", "pass")
	assert.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Equal(t, "user", creds.Username())
	assert.Equal(t, "pass", creds.Password())
}

func TestDefaultGmailConfig(t *testing.T) {
	config, err := DefaultGmailConfig("from@gmail.com", "From Name")
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, gmailServer, config.Server())
	assert.Equal(t, defaultSMTPPort, config.Port())
	assert.Equal(t, StartTLS, config.Encryption())
	assert.Equal(t, "from@gmail.com", config.FromAddress())
	assert.Equal(t, "From Name", config.FromName())
}

func TestDefaultOutlookConfig(t *testing.T) {
	config, err := DefaultOutlookConfig("from@outlook.com", "From Name")
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, outlookServer, config.Server())
	assert.Equal(t, defaultSMTPPort, config.Port())
	assert.Equal(t, StartTLS, config.Encryption())
	assert.Equal(t, "from@outlook.com", config.FromAddress())
	assert.Equal(t, "From Name", config.FromName())
}

func TestDefaultAmazonSESConfig(t *testing.T) {
	config, err := DefaultAmazonSESConfig("us-west-2", "from@ses.com", "From Name")
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, "email-smtp.us-west-2.amazonaws.com", config.Server())
	assert.Equal(t, defaultSMTPPort, config.Port())
	assert.Equal(t, StartTLS, config.Encryption())
	assert.Equal(t, "from@ses.com", config.FromAddress())
	assert.Equal(t, "From Name", config.FromName())
}

func TestSetCredentials(t *testing.T) {
	config, err := DefaultGmailConfig("from@gmail.com", "From Name")
	assert.NoError(t, err)

	err = SetCredentials(config, "newuser", "newpass")
	assert.NoError(t, err)
	assert.True(t, config.HasCredentials())
	assert.Equal(t, "newuser", config.Credentials().Username())
	assert.Equal(t, "newpass", config.Credentials().Password())
}

func TestSetReplyTo(t *testing.T) {
	config, err := DefaultGmailConfig("from@gmail.com", "From Name")
	assert.NoError(t, err)

	err = SetReplyTo(config, "replyto@gmail.com")
	assert.NoError(t, err)
	assert.Equal(t, "replyto@gmail.com", config.ReplyTo())
}

func TestSetTemplatePath(t *testing.T) {
	config, err := DefaultGmailConfig("from@gmail.com", "From Name")
	assert.NoError(t, err)

	err = SetTemplatePath(config, "/new/path/to/template")
	assert.NoError(t, err)
	assert.Equal(t, "/new/path/to/template", config.TemplatePath())
}

func TestValidateSMTPConfiguration(t *testing.T) {
	creds, err := NewSMTPCredentials("user", "pass")
	assert.NoError(t, err)

	config, err := NewSMTPConfig("", 587, "from@example.com", "From Name", "replyto@example.com", "/path/to/template", StartTLS, creds)
	assert.Error(t, err)
	assert.Nil(t, config)

	config, err = NewSMTPConfig("smtp.example.com", -1, "from@example.com", "From Name", "replyto@example.com", "/path/to/template", StartTLS, creds)
	assert.Error(t, err)
	assert.Nil(t, config)

	config, err = NewSMTPConfig("smtp.example.com", 587, "invalid-email", "From Name", "replyto@example.com", "/path/to/template", StartTLS, creds)
	assert.Error(t, err)
	assert.Nil(t, config)
}

func TestValidateSMTPCredentials(t *testing.T) {
	creds, err := NewSMTPCredentials("", "pass")
	assert.Error(t, err)
	assert.Nil(t, creds)

	creds, err = NewSMTPCredentials("user", "")
	assert.Error(t, err)
	assert.Nil(t, creds)
}
