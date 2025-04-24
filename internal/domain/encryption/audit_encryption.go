package domain

import domain "github.com/vigiloauth/vigilo/internal/domain/audit"

type AuditEncryptor interface {
	// EncryptAuditEvent encrypts the sensitive fields of an AuditEvent in place.
	// This should be called before persisting an audit event to ensure PII and
	// other sensitive data is properly secured.
	//
	// Parameters:
	//   - event: Pointer to the AuditEvent to be encrypted. The event will be modified in place.
	//
	// Returns:
	//   - error: An error if encryption of any field fails, nil on success
	EncryptAuditEvent(event *domain.AuditEvent) error

	// DecryptAuditEvent decrypts the sensitive fields of an AuditEvent in place.
	// This should be called when retrieving an audit event for processing or display.
	//
	// Parameters:
	//   - event: Pointer to the AuditEvent to be decrypted. The event will be modified in place.
	//
	// Returns:
	//   - error: An error if decryption of any field fails, nil on success
	DecryptAuditEvent(event *domain.AuditEvent) error

	EncryptString(value string) (string, error)
}
