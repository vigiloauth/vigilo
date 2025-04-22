package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ domain.AuditLogger = (*auditLogger)(nil)

type auditLogger struct {
	auditRepo domain.AuditRepository
	logger    *config.Logger
	module    string
}

func NewAuditLogger(auditRepo domain.AuditRepository) domain.AuditLogger {
	return &auditLogger{
		auditRepo: auditRepo,
		logger:    config.GetServerConfig().Logger(),
		module:    "Audit Logger",
	}
}

// StoreEvent saves an AuditEvent to the repository.
// If an error occurrs storing the audit event, no error will be returned so that the flow is not disrupted.
//
// Parameters:
//   - ctx Context: The context for managing timeouts, cancellations, and for storing/retrieving event metadata.
//   - eventType EventType: The type of event to store.
//   - success bool: True if the event was successful, otherwise false.
//   - action ActionType: The action that is to be audited.
//   - method MethodType: The method used (password, email, etc).
//   - err error: The error if applicable, otherwise nil.
func (a *auditLogger) StoreEvent(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
	var errCode string
	if e, ok := err.(*errors.VigiloAuthError); ok {
		errCode = e.ErrorCode
	}

	event := domain.NewAuditEvent(ctx, eventType, success, action, method, errCode)
	if err := a.auditRepo.StoreAuditEvent(ctx, event); err != nil {
		a.logger.Error(a.module, common.GetRequestID(ctx), "[StoreEvent]: Failed to store audit event: %v", err)
	}
}

// DeleteOldEvents deletes audit events older than the specified timestamp.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - olderThan time.Time: Events older than this timestamp will be deleted.
//
// Returns:
//   - error: An error if deletion fails, otherwise nil.
func (a *auditLogger) DeleteOldEvents(ctx context.Context, olderThan time.Time) error {
	events, err := a.auditRepo.GetAuditEvents(ctx, map[string]any{}, time.Time{}, olderThan, 1000, 0)
	if err != nil {
		a.logger.Error(a.module, "", "[DeleteOldEvents]: An error retrieving old audit events: %v", err)
		return errors.NewInternalServerError()
	}

	if len(events) == 0 {
		a.logger.Info(a.module, "", "[DeleteOldEvents]: No audit events to remove in the given time period")
		return nil
	}

	for _, event := range events {
		if err := a.auditRepo.DeleteEvent(ctx, event.EventID); err != nil {
			a.logger.Error(a.module, "", "[DeleteOldEvents]: An error occurred deleting event ID=[%s]: %v", event.EventID, err)
			return errors.NewInternalServerError()
		}
	}

	return nil
}
