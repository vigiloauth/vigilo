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
	resetURL   string = "https://example.com/reset"
	resetToken string = "token123"
)

func setupSMTPConfigForPasswordReset() *config.SMTPConfig {
	smtpConfig := &config.SMTPConfig{}
	smtpConfig.SetServer(TestSMTPServer)
	smtpConfig.SetPort(TestSMTPPort)
	smtpConfig.SetFromAddress(TestFromAddress)
	smtpConfig.SetEncryption(config.None)

	cfg := config.NewServerConfig(
		config.WithSMTPConfig(smtpConfig),
	)

	return cfg.SMTPConfig()
}

func createPasswordResetRequest() EmailRequest {
	return EmailRequest{
		Recipient:     TestRecipient,
		ApplicationID: TestApplicationID,
		PasswordResetRequest: &PasswordResetRequest{
			ResetURL:   resetURL,
			ResetToken: resetToken,
		},
	}
}

func TestNewPasswordResetEmailService_ValidSMTPConfig(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, err := NewPasswordResetEmailService()

	assert.NoError(t, err, "failed to initialize password reset service")
	assert.NotNil(t, ps)
}

func TestNewPasswordResetEmailService_InvalidSMTPConfig(t *testing.T) {
	invalidSMTPConfig := setupSMTPConfigForPasswordReset()
	invalidSMTPConfig.SetPort(0)
	invalidSMTPConfig.SetServer("")

	ps, err := NewPasswordResetEmailService()
	assert.Error(t, err, "failed to initialize password reset service")
	assert.Nil(t, ps)
}

func TestNewPasswordResetEmailService_LoadingTemplateFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetTemplatePath("/invalid/template/path")

	_, err := NewPasswordResetEmailService()
	assert.Error(t, err, "expected an error while loading email template")
}

func TestPasswordResetEmailService_GenerateEmail(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, _ := NewPasswordResetEmailService()

	request := createPasswordResetRequest()
	emailRequest := ps.GenerateEmail(request)

	assert.Equal(t, request.Recipient, emailRequest.Recipient, "recipients are not equal")
	assert.Contains(t, emailRequest.Subject, "Password Reset Request")
	assert.Equal(t, emailRequest.TemplateData.ResetURL, resetURL)
}

func TestPasswordResetEmailService_SendEmailFailure(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, _ := NewPasswordResetEmailService()

	request := createPasswordResetRequest()
	err := ps.SendEmail(request)
	assert.Error(t, err, "expected an error while sending an email")
}

func TestPasswordResetEmailService_TestConnection_Success(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
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

func TestPasswordResetEmailService_TestConnection_StartTLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetEncryption(config.StartTLS)
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
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

func TestPasswordResetEmailService_TestConnection_AuthenticationFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetEncryption(config.None)
	smtpConfig.SetCredentials("username", "password")

	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
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

func TestPasswordResetEmailService_TestConnection_TLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetEncryption(config.TLS)
	ps, _ := NewPasswordResetEmailService()

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
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

func TestPasswordResetEmailService_TestConnection_UnsupportedEncryptionType(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetEncryption("unsupported_encryption")
	ps, _ := NewPasswordResetEmailService()

	err := ps.TestConnection()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Unsupported encryption type")
}

func TestPasswordResetEmailService_TestConnection_Failure(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, _ := NewPasswordResetEmailService()

	err := ps.TestConnection()
	assert.Error(t, err)
}

func TestPasswordResetEmailService_ProcessQueue_EmptyQueue(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	ps, _ := NewPasswordResetEmailService()

	ps.ProcessQueue() // Should not panic or throw any error
}

func TestPasswordResetEmailService_ProcessQueue_SkipsExpiredToken(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetMaxRetries(3)
	smtpConfig.SetRetryDelay(1 * time.Millisecond)

	ps, err := NewPasswordResetEmailService()
	assert.NoError(t, err)

	expiredRequest := createPasswordResetRequest()
	pastTime := time.Now().Add(-1 * time.Hour)
	expiredRequest.PasswordResetRequest.TokenExpiry = pastTime

	validRequest := createPasswordResetRequest()
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

func TestPasswordResetEmailService_ProcessQueue_Retry(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetMaxRetries(2)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetEmailService()

	request := createPasswordResetRequest()
	ps.SendEmail(request)
	ps.ProcessQueue()

	queueStatus, _ := ps.GetQueueStatus()
	assert.Equal(t, 1, queueStatus, "expected only one request to be in the queue")
}

func TestPasswordResetEmailService_StartQueueProcessor(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetFromAddress(TestFromAddress)
	smtpConfig.SetEncryption(config.StartTLS)
	smtpConfig.SetRetryDelay(1 * time.Second)

	ps, _ := NewPasswordResetEmailService()

	go ps.StartQueueProcessor(2 * time.Second)
	time.Sleep(5 * time.Second)

	status, _ := ps.GetQueueStatus()
	assert.Equal(t, 0, status, "expected no requests to be in the queue")
}

func TestPasswordResetEmailService_SetTemplate_Success(t *testing.T) {
	templateContent := "<html><body><h1>Password Reset Template</h1></body></html>"
	tmpFile, err := os.CreateTemp("", "email_template_*.html")
	assert.NoError(t, err, "failed to create temporary template file.")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(templateContent)
	assert.NoError(t, err, "failed to write to template file")
	tmpFile.Close()

	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetTemplatePath(tmpFile.Name())

	ps, _ := NewPasswordResetEmailService()
	err = ps.SetTemplate(templateContent)
	assert.NoError(t, err, "failed to set template")
}

func TestPasswordResetEmailService_SMTPConfigValidation_EmptyFields(t *testing.T) {
	smtpConfig := setupSMTPConfigForPasswordReset()
	smtpConfig.SetPort(0)
	smtpConfig.SetEncryption("")
	smtpConfig.SetFromAddress("")

	_, err := NewPasswordResetEmailService()
	assert.Error(t, err, "expected an error when validating an invalid SMTP configuration")
}
