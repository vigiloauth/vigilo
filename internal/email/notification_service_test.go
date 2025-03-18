package email

import (
	"os"
	"testing"
	"time"

	smtpmock "github.com/mocktools/go-smtp-mock/v2"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
)

func setupSMTPConfigForEmailNotification() *config.SMTPConfig {
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

func TestEmailNotificationService_ValidSMTPConfig(t *testing.T) {
	setupSMTPConfigForEmailNotification()
	es, err := NewEmailNotificationService()

	assert.NoError(t, err, "failed to initialize email notification service")
	assert.NotNil(t, es)
}

func TestEmailNotificationService_InvalidSMTPConfig(t *testing.T) {
	invalidSMTPConfig := setupSMTPConfigForEmailNotification()
	invalidSMTPConfig.SetPort(0)
	invalidSMTPConfig.SetServer("")

	es, err := NewEmailNotificationService()
	assert.Error(t, err, "expected an error when initializing email notification service")
	assert.Nil(t, es)
}

func TestEmailNotificationService_LoadingTemplateFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetTemplatePath("/invalid/template/path")

	_, err := NewPasswordResetEmailService()
	assert.Error(t, err, "Expected an error while loading email template")
}

func TestEmailNotificationService_GenerateEmail(t *testing.T) {
	setupSMTPConfigForPasswordReset()
	es, _ := NewEmailNotificationService()

	request := createEmailNotificationRequest()
	emailRequest := es.GenerateEmail(request)

	assert.Equal(t, request.Recipient, emailRequest.Recipient, "recipients are not equal")
	assert.Contains(t, emailRequest.Subject, "Account Locked Notification")
}

func TestEmailNotificationService_SendEmailFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetCredentials("username", "password")

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	request := createEmailNotificationRequest()
	err = es.SendEmail(request)
	assert.Error(t, err, "expected an error sending an email")
}

func TestEmailNotificationService_TestConnection_Success(t *testing.T) {
	setupSMTPConfigForEmailNotification()
	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err = es.TestConnection()
	assert.NoError(t, err, "error when testing connection")
}

func TestEmailNotificationService_TestConnection_StartTLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetEncryption(config.StartTLS)

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	expectedMessage := "starttls failed: failed to create SMTP Client"
	err = es.TestConnection()

	assert.Error(t, err, "expected an error when using StartTLS")
	assert.Contains(t, err.Error(), expectedMessage)
}

func TestEmailNotificationService_TestConnection_AuthenticationFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetEncryption(config.None)
	smtpConfig.SetCredentials("username", "password")

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err = es.TestConnection()
	assert.Error(t, err, "expected an error when authenticating credentials")
}

func TestEmailNotificationService_TestConnection_TLSFailure(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetEncryption(config.TLS)

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       TestSMTPServer,
		PortNumber:        TestSMTPPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start mock SMTP server: %v", err)
	}
	defer server.Stop()

	err = es.TestConnection()
	assert.Error(t, err, "expected TLS failure due to invalid handshake")
}

func TestEmailNotificationService_TestConnection_UnsupportedEncryptionType(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetEncryption("unsupported_encryption")

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	expectedMessage := "`unsupported_encryption` is unsupported: failed to create SMTP Client"
	err = es.TestConnection()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), expectedMessage)
}

func TestEmailNotificationService_TestConnection_Failure(t *testing.T) {
	setupSMTPConfigForEmailNotification()
	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	err = es.TestConnection()
	assert.Error(t, err)
}

func TestEmailNotificationService_ProcessQueue_EmptyQueue(t *testing.T) {
	setupSMTPConfigForEmailNotification()
	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	es.ProcessQueue() // Should not panic or throw any error
}

func TestEmailNotificationService_ProcessQueue_Retry(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetEncryption(config.TLS)
	smtpConfig.SetMaxRetries(3)
	smtpConfig.SetRetryDelay(1 * time.Millisecond)

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	request := createEmailNotificationRequest()
	es.SendEmail(request)
	go es.StartQueueProcessor(1 * time.Millisecond)

	queueStatus, _ := es.GetQueueStatus()
	assert.Equal(t, 1, queueStatus, "expected only one request to be present in queue")
}

func TestEmailNotificationService_StartQueueProcessor(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetFromAddress(TestFromAddress)
	smtpConfig.SetEncryption(config.StartTLS)
	smtpConfig.SetRetryDelay(1 * time.Second)

	es, err := NewEmailNotificationService()
	assert.NoError(t, err, "failed to initialize email notification service")

	go es.StartQueueProcessor(2 * time.Second)
	time.Sleep(5 * time.Second)

	status, _ := es.GetQueueStatus()
	assert.Equal(t, 0, status, "expected no request to be in queue")
}

func TestEmailNotificationService_SetTemplate_Success(t *testing.T) {
	templateContent := "<html><body><h1>Password Reset Template</h1></body></html>"
	tmpFile, err := os.CreateTemp("", "email_template_*.html")
	assert.NoError(t, err, "failed to create temporary template file.")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(templateContent)
	assert.NoError(t, err, "failed to write to template file")
	tmpFile.Close()

	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetTemplatePath(tmpFile.Name())

	es, _ := NewEmailNotificationService()
	err = es.SetTemplate(templateContent)
	assert.NoError(t, err, "failed to set template")
}

func TestEmailNotificationService_SMTPConfigValidation_EmptyFields(t *testing.T) {
	smtpConfig := setupSMTPConfigForEmailNotification()
	smtpConfig.SetPort(0)
	smtpConfig.SetEncryption("")
	smtpConfig.SetFromAddress("")

	_, err := NewEmailNotificationService()
	assert.Error(t, err, "expected an error when validating an invalid SMTP configuration")
}

func createEmailNotificationRequest() EmailRequest {
	return EmailRequest{
		Recipient:     TestRecipient,
		ApplicationID: TestApplicationID,
	}
}
