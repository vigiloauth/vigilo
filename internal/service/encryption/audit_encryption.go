package service

import (
	"encoding/json"

	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	encryption "github.com/vigiloauth/vigilo/v2/internal/domain/encryption"
)

var _ encryption.AuditEncryptor = (*auditEncryptor)(nil)

type auditEncryptor struct {
	secretKey  string
	encryption encryption.EncryptionService
}

func NewAuditEncryptor(secretKeyProvider func() string, encryptor encryption.EncryptionService) encryption.AuditEncryptor {
	return &auditEncryptor{
		secretKey:  secretKeyProvider(),
		encryption: encryptor,
	}
}

// EncryptAuditEvent encrypts the sensitive fields of an AuditEvent in place.
// This should be called before persisting an audit event to ensure PII and
// other sensitive data is properly secured.
//
// Parameters:
//   - event: Pointer to the AuditEvent to be encrypted. The event will be modified in place.
//
// Returns:
//   - error: An error if encryption of any field fails, nil on success
func (a *auditEncryptor) EncryptAuditEvent(event *audit.AuditEvent) error {
	encryptedUserID, err := a.encryption.EncryptString(event.UserID, a.secretKey)
	if err != nil {
		return err
	}
	event.UserID = encryptedUserID

	encryptedIP, err := a.encryption.EncryptString(event.IP, a.secretKey)
	if err != nil {
		return err
	}
	event.IP = encryptedIP

	if len(event.Details) > 0 {
		encDetails, err := a.encryption.EncryptBytes(event.Details, a.secretKey)
		if err != nil {
			return err
		}
		event.Details = json.RawMessage([]byte(encDetails))
	}

	if event.SessionID != "" {
		encSessionID, err := a.encryption.EncryptString(event.SessionID, a.secretKey)
		if err != nil {
			return err
		}
		event.SessionID = encSessionID
	}

	if event.UserAgent != "" {
		encUserAgent, err := a.encryption.EncryptString(event.UserAgent, a.secretKey)
		if err != nil {
			return err
		}
		event.UserAgent = encUserAgent
	}

	if event.ErrCode != "" {
		encErrCode, err := a.encryption.EncryptString(event.ErrCode, a.secretKey)
		if err != nil {
			return err
		}
		event.ErrCode = encErrCode
	}

	return nil
}

// DecryptAuditEvent decrypts the sensitive fields of an AuditEvent in place.
// This should be called when retrieving an audit event for processing or display.
//
// Parameters:
//   - event: Pointer to the AuditEvent to be decrypted. The event will be modified in place.
//
// Returns:
//   - error: An error if decryption of any field fails, nil on success
func (a *auditEncryptor) DecryptAuditEvent(event *audit.AuditEvent) error {
	if event.UserID != "" {
		plainUserID, err := a.encryption.DecryptString(event.UserID, a.secretKey)
		if err != nil {
			return err
		}
		event.UserID = plainUserID
	}

	if event.IP != "" {
		plainIP, err := a.encryption.DecryptString(event.IP, a.secretKey)
		if err != nil {
			return err
		}
		event.IP = plainIP
	}

	if len(event.Details) > 0 {
		plainDetails, err := a.encryption.DecryptBytes(string(event.Details), a.secretKey)
		if err != nil {
			return err
		}
		event.Details = plainDetails
	}

	if event.SessionID != "" {
		plainSessionID, err := a.encryption.DecryptString(event.SessionID, a.secretKey)
		if err != nil {
			return err
		}
		event.SessionID = plainSessionID
	}

	if event.UserAgent != "" {
		plainUserAgent, err := a.encryption.DecryptString(event.UserAgent, a.secretKey)
		if err != nil {
			return err
		}
		event.UserAgent = plainUserAgent
	}

	if event.ErrCode != "" {
		plainErrCode, err := a.encryption.DecryptString(event.ErrCode, a.secretKey)
		if err != nil {
			return err
		}
		event.ErrCode = plainErrCode
	}

	return nil
}

func (a *auditEncryptor) EncryptString(value string) (string, error) {
	return a.encryption.EncryptString(value, a.secretKey)
}
