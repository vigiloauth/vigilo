package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/encryption"
)

const (
	userID    string = "user-98756"
	ip        string = "192.168.1.10"
	userAgent string = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
	sessionID string = "sess-11122"
)

func TestAuditEncryptor_EncryptAuditEvent(t *testing.T) {
	tests := []struct {
		name       string
		wantErr    bool
		event      *domain.AuditEvent
		encryption *mocks.MockEncryptionService
	}{
		{
			name:    "Successful encryption",
			wantErr: false,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return crypto.EncryptString(plainStr, secretKey)
				},
				EncryptBytesFunc: func(plainBytes []byte, secretKey string) (string, error) {
					return crypto.EncryptBytes(plainBytes, secretKey)
				},
			},
		},
		{
			name:    "Error is returned when failing to encrypt the user ID",
			wantErr: true,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when failing to encrypt the IP address",
			wantErr: true,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when failing to encrypt the event details",
			wantErr: true,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return crypto.EncryptString(plainStr, secretKey)
				},
				EncryptBytesFunc: func(plainBytes []byte, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when failing to encrypt the session ID",
			wantErr: true,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when failing to encrypt the error code",
			wantErr: true,
			event:   getAuditEvent(),
			encryption: &mocks.MockEncryptionService{
				EncryptStringFunc: func(plainStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewAuditEncryptor(getSecretKey, test.encryption)
			originalAuditEvent := *test.event
			err := service.EncryptAuditEvent(test.event)

			if test.wantErr {
				assert.Error(t, err, "An error was expected when encrypting the audit event")
			} else {
				assert.NoError(t, err, "No error was expected when encrypting the audit event")
				assert.NotEqual(t, originalAuditEvent.UserID, test.event.UserID)
				assert.NotEqual(t, originalAuditEvent.IP, test.event.IP)
				assert.NotEqual(t, originalAuditEvent.UserAgent, test.event.UserAgent)
				assert.NotEqual(t, originalAuditEvent.ErrCode, test.event.ErrCode)
			}
		})
	}
}

func TestAuditEncryptor_DecryptAuditEvent(t *testing.T) {
	testSecretKey := getSecretKey()
	tests := []struct {
		name       string
		wantErr    bool
		event      *domain.AuditEvent
		encryption *mocks.MockEncryptionService
	}{
		{
			name:    "Success",
			wantErr: false,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return crypto.DecryptString(encryptedStr, testSecretKey)
				},
				DecryptBytesFunc: func(encryptedBytes, secretKey string) ([]byte, error) {
					return crypto.DecryptBytes(encryptedBytes, testSecretKey)
				},
			},
		},
		{
			name:    "Error is returned when decrypting the user ID",
			wantErr: true,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when decrypting the IP address",
			wantErr: true,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when decrypting the user agent",
			wantErr: true,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when decrypting the session ID",
			wantErr: true,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned when decrypting the event details",
			wantErr: true,
			event:   getEncryptedAuditEvent(testSecretKey),
			encryption: &mocks.MockEncryptionService{
				DecryptStringFunc: func(encryptedStr, secretKey string) (string, error) {
					return crypto.EncryptString(encryptedStr, testSecretKey)
				},
				DecryptBytesFunc: func(encryptedBytes, secretKey string) ([]byte, error) {
					return nil, errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewAuditEncryptor(func() string { return testSecretKey }, test.encryption)

			originalAuditEvent := *test.event
			err := service.DecryptAuditEvent(test.event)

			if test.wantErr {
				assert.Error(t, err, "An error was expected when encrypting the audit event")
			} else {
				assert.NoError(t, err, "No error was expected when encrypting the audit event")
				assert.NotEqual(t, originalAuditEvent.UserID, test.event.UserID)
				assert.NotEqual(t, originalAuditEvent.IP, test.event.IP)
				assert.NotEqual(t, originalAuditEvent.UserAgent, test.event.UserAgent)
				assert.NotEqual(t, originalAuditEvent.ErrCode, test.event.ErrCode)
			}
		})
	}
}

func getAuditEvent() *domain.AuditEvent {
	details := map[string]string{
		"action": "login",
		"method": "password",
	}
	detailsJSON, _ := json.Marshal(details)

	return &domain.AuditEvent{
		EventID:   "evt-12345",
		Timestamp: time.Now(),
		EventType: "USER_AUTH",
		Success:   true,
		UserID:    userID,
		IP:        ip,
		UserAgent: userAgent,
		RequestID: "req-54321",
		Details:   detailsJSON,
		SessionID: sessionID,
		ErrCode:   errors.ErrCodeAccessDenied,
	}
}

func getEncryptedAuditEvent(secretKey string) *domain.AuditEvent {
	event := getAuditEvent()
	event.UserID, _ = crypto.EncryptString(event.UserID, secretKey)
	event.IP, _ = crypto.EncryptString(event.IP, secretKey)
	event.UserAgent, _ = crypto.EncryptString(event.UserAgent, secretKey)
	event.SessionID, _ = crypto.EncryptString(event.SessionID, secretKey)
	event.ErrCode, _ = crypto.EncryptString(event.ErrCode, secretKey)
	detailsStr, _ := crypto.EncryptBytes([]byte(event.Details), secretKey)
	event.Details = json.RawMessage(detailsStr)
	return event
}

func getSecretKey() string {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}
