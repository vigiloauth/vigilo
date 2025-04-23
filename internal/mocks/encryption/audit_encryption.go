package mocks

import (
	audit "github.com/vigiloauth/vigilo/internal/domain/audit"
	encryption "github.com/vigiloauth/vigilo/internal/domain/encryption"
)

var _ encryption.AuditEncryptor = (*MockAuditEncryptor)(nil)

type MockAuditEncryptor struct {
	EncryptAuditEventFunc func(event *audit.AuditEvent) error
	DecryptAuditEventFunc func(event *audit.AuditEvent) error
}

func (m *MockAuditEncryptor) EncryptAuditEvent(event *audit.AuditEvent) error {
	return m.EncryptAuditEventFunc(event)
}

func (m *MockAuditEncryptor) DecryptAuditEvent(event *audit.AuditEvent) error {
	return m.DecryptAuditEventFunc(event)
}
