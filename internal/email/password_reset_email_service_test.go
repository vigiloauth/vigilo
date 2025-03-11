package email

import (
	"os"
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
)

const (
	smtpServer        string = "localhost"
	smtpPort          int    = 2525
	invalidSMTPServer string = "invalid-smt-server.com"
	fromAddress       string = "no-reply@example.com"
	recipient         string = "user@example.com"
	applicationID     string = "TestApp"
	resetURL          string = "https://example.com/reset"
	resetToken        string = "token123"
)

func setupSMTPConfig() *config.SMTPConfig {
	smtpConfig := &config.SMTPConfig{}
	smtpConfig.SetServer(smtpServer)
	smtpConfig.SetPort(smtpPort)
	smtpConfig.SetFromAddress(fromAddress)
	smtpConfig.SetEncryption(config.None)

	cfg := config.NewServerConfig(
		config.WithSMTPConfig(smtpConfig),
	)

	return cfg.SMTPConfig()
}

func createRequest() EmailRequest {
	return EmailRequest{
		Recipient:     recipient,
		ApplicationID: applicationID,
		PasswordResetRequest: &PasswordResetRequest{
			ResetURL:   resetURL,
			ResetToken: resetToken,
		},
	}
}

func TestNewPasswordResetEmailService_ValidSMTPConfig(t *testing.T) {
	setupSMTPConfig()
	ps, err := NewPasswordResetEmailService()

	assert.NoError(t, err, "failed to initialize password reset service")
	assert.NotNil(t, ps)
}

func TestNewPasswordResetEmailService_InvalidSMTPConfig(t *testing.T) {
	invalidSMTPConfig := setupSMTPConfig()
	invalidSMTPConfig.SetPort(0)
	invalidSMTPConfig.SetServer("")

	ps, err := NewPasswordResetEmailService()
	assert.Error(t, err, "failed to initialize password reset service")
	assert.Nil(t, ps)
}

func TestNewPasswordResetEmailService_LoadingTemplateFailure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetTemplatePath("/invalid/template/path")

	_, err := NewPasswordResetEmailService()
	assert.Error(t, err, "expected an error while loading email template")
}

func TestGenerateEmail(t *testing.T) {
	setupSMTPConfig()
	ps, _ := NewPasswordResetEmailService()

	request := createRequest()
	emailRequest := ps.GenerateEmail(request)

	assert.Equal(t, request.Recipient, emailRequest.Recipient, "recipients are not equal")
	assert.Contains(t, emailRequest.Subject, "Password Reset Request")
	assert.Equal(t, emailRequest.TemplateData.ResetURL, resetURL)
}

func TestSendEmail_Failure(t *testing.T) {
	setupSMTPConfig()
	ps, _ := NewPasswordResetEmailService()

	request := createRequest()
	err := ps.SendEmail(request)
	assert.Error(t, err, "expected an error while sending an email")
}

func TestTestConnection_Success(t *testing.T) {
	setupSMTPConfig()
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        smtpPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err := ps.TestConnection()
	assert.NoError(t, err, "expected no error when testing connection")
}

func TestTestConnection_StartTLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetEncryption(config.StartTLS)
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        smtpPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err := ps.TestConnection()
	assert.Error(t, err, "expected an error when testing with StartTLS encryption")
	assert.Contains(t, err.Error(), "StartTLS failed")
}

func TestTestConnection_FailureCreatingTLSClient(t *testing.T) {}

func TestTestConnection_AuthenticationFailure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetEncryption(config.None)
	smtpConfig.SetCredentials("username", "password")

	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        smtpPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err := ps.TestConnection()
	assert.Error(t, err, "expected an error when authenticating credentials")
	assert.Contains(t, err.Error(), "SMTP authentication failed")
}

func TestTestConnection_TLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetEncryption(config.TLS)
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        smtpPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err := ps.TestConnection()
	assert.Error(t, err, "expected TLS failure due to invalid handshake")
}

func TestTestConnection_UnsupportedEncryptionType(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetEncryption("unsupported_encryption")
	ps, _ := NewPasswordResetEmailService()

	err := ps.TestConnection()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported encryption type")
}

func TestTestConnection_Failure(t *testing.T) {
	setupSMTPConfig()
	ps, _ := NewPasswordResetEmailService()

	err := ps.TestConnection()
	assert.Error(t, err)
}

func TestProcessQueue_EmptyQueue(t *testing.T) {
	setupSMTPConfig()
	ps, _ := NewPasswordResetEmailService()

	ps.ProcessQueue() // Should not panic or throw any error
}

func TestProcessQueue_SkipsExpiredToken(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetMaxRetries(3)
	smtpConfig.SetRetryDelay(1 * time.Millisecond)

	ps, err := NewPasswordResetEmailService()
	assert.NoError(t, err)

	expiredRequest := createRequest()
	pastTime := time.Now().Add(-1 * time.Hour)
	expiredRequest.PasswordResetRequest.TokenExpiry = pastTime

	validRequest := createRequest()
	validRequest.Recipient = "recipient2@example.com"

	futureTime := time.Now().Add(24 * time.Hour)
	validRequest.PasswordResetRequest.TokenExpiry = futureTime

	err = ps.SendEmail(expiredRequest)
	assert.Error(t, err, "Expected error when sending email")

	err = ps.SendEmail(validRequest)
	assert.Error(t, err, "Expected error when sending email")

	initialQueueSize, recipients := ps.GetQueueStatus()
	assert.Equal(t, 2, initialQueueSize, "expected two requests in the queue")
	assert.Contains(t, recipients, expiredRequest.Recipient)
	assert.Contains(t, recipients, validRequest.Recipient)

	time.Sleep(2 * time.Millisecond)

	ps.ProcessQueue()
	queueSize, recipients := ps.GetQueueStatus()
	assert.Equal(t, 1, queueSize, "expected only one request to remain in the queue")
	assert.NotContains(t, recipients, expiredRequest.Recipient,
		"expired request should have been removed from the queue")
	assert.Contains(t, recipients, validRequest.Recipient, "valid request should still be in the queue")
}

func TestProcessQueue_Retry(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetMaxRetries(2)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetEmailService()

	request := createRequest()
	ps.SendEmail(request)
	ps.ProcessQueue()

	queueStatus, _ := ps.GetQueueStatus()
	assert.Equal(t, 1, queueStatus, "expected only one request to be in the queue")
}

func TestStartQueueProcessor(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetFromAddress(fromAddress)
	smtpConfig.SetEncryption(config.StartTLS)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetEmailService()

	go ps.StartQueueProcessor(2 * time.Second)
	time.Sleep(5 * time.Second)

	status, _ := ps.GetQueueStatus()
	assert.Equal(t, 0, status, "expected no requests to be in the queue")
}

func TestSetTemplate_Success(t *testing.T) {
	templateContent := "<html><body><h1>Password Reset Template</h1></body></html>"
	tmpFile, err := os.CreateTemp("", "email_template_*.html")
	assert.NoError(t, err, "failed to create temporary template file.")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(templateContent)
	assert.NoError(t, err, "failed to write to template file")
	tmpFile.Close()

	smtpConfig := setupSMTPConfig()
	smtpConfig.SetTemplatePath(tmpFile.Name())

	ps, _ := NewPasswordResetEmailService()
	err = ps.SetTemplate(templateContent)
	assert.NoError(t, err, "failed to set template")
}

func TestSMTPConfigValidation_EmptyFields(t *testing.T) {
	smtpConfig := setupSMTPConfig()
	smtpConfig.SetPort(0)
	smtpConfig.SetEncryption("")
	smtpConfig.SetFromAddress("")

	_, err := NewPasswordResetEmailService()
	assert.Error(t, err, "expected an error when validating an invalid SMTP configuration")
}
