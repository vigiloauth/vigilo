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
	testUsername          string = "username"
	testPassword          string = "password"
	testRecipient         string = "recipient@mail.com"
	testFromAddress       string = "no-reply@example.com"
	testApplicationID     string = "VigiloTest"
	testValidSMTPServer   string = "localhost"
	testSMTPPort          int    = 2525
	testInvalidSMTPServer string = "invalid-smt-server.com"
)

func setupTestSMTPConfig() *config.SMTPConfig {
	smtpConfig := &config.SMTPConfig{}
	smtpConfig.SetServer(testValidSMTPServer)
	smtpConfig.SetPort(testSMTPPort)
	smtpConfig.SetFromAddress(testFromAddress)
	smtpConfig.SetEncryption(config.None)

	cfg := config.NewServerConfig(
		config.WithSMTPConfig(smtpConfig),
	)

	return cfg.SMTPConfig()
}

func TestBaseEmailService_Initialize(t *testing.T) {
	t.Run("Error is thrown due to nil SMTP Config", func(t *testing.T) {
		es := &BaseEmailService{}
		err := es.Initialize()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SMTP configuration has not been provided")
	})

	t.Run("Success", func(t *testing.T) {
		setupTestSMTPConfig()
		es := &BaseEmailService{}
		err := es.Initialize()

		assert.NoError(t, err)
	})

	t.Run("Error is thrown validating SMTP Config", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetFromAddress("")

		expectedErrorMessage := "failed to validate SMTP Credentials: invalid or empty 'from_address'"
		es := &BaseEmailService{}
		err := es.Initialize()

		assert.Error(t, err)
		assert.Equal(t, expectedErrorMessage, err.Error())
	})

	t.Run("Error is thrown loading email template", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetTemplatePath("/invalid/template/path")

		es := &BaseEmailService{}
		err := es.Initialize()

		assert.Error(t, err)
	})
}

func TestBaseEmailService_SetTemplate_Success(t *testing.T) {
	templateContent := "<html><body><h1>Password Reset Template</h1></body></html>"
	tmpFile, err := os.CreateTemp("", "email_template_*.html")
	assert.NoError(t, err, "failed to create temporary template file.")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(templateContent)
	assert.NoError(t, err, "failed to write to template file")
	tmpFile.Close()

	smtpConfig := setupTestSMTPConfig()
	smtpConfig.SetTemplatePath(tmpFile.Name())

	es := &BaseEmailService{}
	err = es.Initialize()

	assert.NoError(t, err)

	err = es.SetTemplate(templateContent)
	assert.NoError(t, err, "failed to set template")
}

func TestBaseEmailService_SendEmail_Error(t *testing.T) {
	cfg := setupTestSMTPConfig()
	cfg.SetCredentials(testUsername, testPassword)

	es := &BaseEmailService{}
	err := es.Initialize()
	assert.NoError(t, err)

	request := createEmailRequest()
	err = es.sendEmail(request)

	assert.Error(t, err)
}

func TestBaseEmailService_TestConnection(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		setupTestSMTPConfig()
		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		server := startTestSMTPServer(t, testValidSMTPServer)
		defer server.Stop()

		err = es.TestConnection()
		assert.NoError(t, err)
	})

	t.Run("StartTLS Failure", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetEncryption(config.StartTLS)

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		server := startTestSMTPServer(t, testValidSMTPServer)
		defer server.Stop()

		err = es.TestConnection()
		assert.Error(t, err)
	})

	t.Run("Authentication Failure", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetEncryption(config.None)
		cfg.SetCredentials(testUsername, testPassword)

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		server := startTestSMTPServer(t, testValidSMTPServer)
		defer server.Stop()

		err = es.TestConnection()
		assert.Error(t, err)
	})

	t.Run("TLS Failure", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetEncryption(config.TLS)

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		server := startTestSMTPServer(t, testValidSMTPServer)
		defer server.Stop()

		err = es.TestConnection()
		assert.Error(t, err)
	})

	t.Run("Unsupported Encryption Type", func(t *testing.T) {
		cfg := setupTestSMTPConfig()
		cfg.SetEncryption("unsupported_encryption")

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		server := startTestSMTPServer(t, testValidSMTPServer)
		defer server.Stop()

		err = es.TestConnection()
		assert.Error(t, err)
	})
}

func TestBaseEmailService_ProcessQueue(t *testing.T) {
	t.Run("Empty Queue should not panic or throw an error", func(t *testing.T) {
		setupTestSMTPConfig()

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		es.ProcessQueue()
	})

	t.Run("Successful Retry", func(t *testing.T) {
		retryDelay := 1 * time.Millisecond
		cfg := setupTestSMTPConfig()
		cfg.SetEncryption(config.TLS)
		cfg.SetMaxRetries(3)
		cfg.SetRetryDelay(retryDelay)

		es := &BaseEmailService{}
		err := es.Initialize()
		assert.NoError(t, err)

		request := createEmailRequest()
		es.SendEmail(request)
		go es.StartQueueProcessor(retryDelay)

		queueStatus, _ := es.GetQueueStatus()
		assert.Equal(t, 1, queueStatus, "expected only one request to be present in the queue")
	})
}

func TestBaseEmailService_StartQueueProcessor(t *testing.T) {
	cfg := setupTestSMTPConfig()
	cfg.SetFromAddress(testFromAddress)
	cfg.SetEncryption(config.StartTLS)
	cfg.SetRetryDelay(1 * time.Second)

	es := &BaseEmailService{}
	err := es.Initialize()
	assert.NoError(t, err)

	go es.StartQueueProcessor(2 * time.Second)
	time.Sleep(5 * time.Second)

	status, _ := es.GetQueueStatus()
	assert.Equal(t, 0, status, "expected no requests to be in the queue")
}

func createEmailRequest() EmailRequest {
	return EmailRequest{
		Recipient:     testRecipient,
		ApplicationID: testApplicationID,
		Subject:       "Email Notification",
	}
}

func startTestSMTPServer(t *testing.T, smtpServer string) *smtpmock.Server {
	cfg := smtpmock.ConfigurationAttr{
		HostAddress:       smtpServer,
		PortNumber:        testSMTPPort,
		LogToStdout:       true,
		LogServerActivity: true,
	}

	server := smtpmock.New(cfg)
	err := server.Start()
	assert.NoError(t, err)
	return server
}
