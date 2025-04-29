package mocks

import (
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	encryption "github.com/vigiloauth/vigilo/v2/internal/domain/encryption"
)

var _ encryption.AuditEncryptor = (*MockAuditEncryptor)(nil)

type MockAuditEncryptor struct {
	EncryptAuditEventFunc func(event *audit.AuditEvent) error
	DecryptAuditEventFunc func(event *audit.AuditEvent) error
	EncryptStringFunc     func(value string) (string, error)
}

func (m *MockAuditEncryptor) EncryptAuditEvent(event *audit.AuditEvent) error {
	return m.EncryptAuditEventFunc(event)
}

func (m *MockAuditEncryptor) DecryptAuditEvent(event *audit.AuditEvent) error {
	return m.DecryptAuditEventFunc(event)
}

func (m *MockAuditEncryptor) EncryptString(value string) (string, error) {
	return m.EncryptStringFunc(value)
}
