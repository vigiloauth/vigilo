package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ audit.AuditLogger = (*auditLogger)(nil)

type auditLogger struct {
	auditRepo audit.AuditRepository
	logger    *config.Logger
	module    string
}

func NewAuditLogger(auditRepo audit.AuditRepository) audit.AuditLogger {
	return &auditLogger{
		auditRepo: auditRepo,
		logger:    config.GetServerConfig().Logger(),
		module:    "Audit Logger",
	}
}

// StoreEvent saves an AuditEvent to the repository.
// If an error occurs storing the audit event, no error will be returned so that the flow is not disrupted.
//
// Parameters:
//   - ctx Context: The context for managing timeouts, cancellations, and for storing/retrieving event metadata.
//   - eventType EventType: The type of event to store.
//   - success bool: True if the event was successful, otherwise false.
//   - action ActionType: The action that is to be audited.
//   - method MethodType: The method used (password, email, etc).
//   - err error: The error if applicable, otherwise nil.
func (a *auditLogger) StoreEvent(
	ctx context.Context,
	eventType audit.EventType,
	success bool,
	action audit.ActionType,
	method audit.MethodType,
	err error,
) {
	requestID := utils.GetRequestID(ctx)

	var errCode string
	if e, ok := err.(*errors.VigiloAuthError); ok { //nolint:errorlint
		errCode = e.ErrorCode
	}

	event := audit.NewAuditEvent(ctx, eventType, success, action, method, errCode)
	if err := a.auditRepo.StoreAuditEvent(ctx, event); err != nil {
		a.logger.Error(a.module, requestID, "[StoreEvent]: Failed to store audit event: %v", err)
		return
	}
}

// GetAuditEvents retrieves audit events that match the provided filters and time range.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - filters map[string]any: A map of filter keys and values to apply.
//   - from time.Time: The start time of the time range to filter events.
//   - to time.Time: The end time of the time range to filter events.
//   - limit int: The maximum number of events to return.
//   - offset int: The number of events to skip (for pagination).
//
// Returns:
//   - []*AuditEvent: A slice of matching audit events.
//   - error: An error if the retrieval fails, otherwise nil.
func (a *auditLogger) GetAuditEvents(ctx context.Context, filters map[string]any, fromStr string, toStr string, limit, offset int) ([]*audit.AuditEvent, error) {
	requestID := utils.GetRequestID(ctx)

	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		a.logger.Error(a.module, requestID, "[GetAuditEvents]: Invalid 'from' timestamp format=[%s]", fromStr)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidInput, "invalid 'from' timestamp - must be in RFC3339 format")
	}

	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		a.logger.Error(a.module, requestID, "[GetAuditEvents]: Invalid 'to' timestamp format=[%s]", toStr)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidInput, "invalid 'to' timestamp - must be in RFC3339 format")
	}

	events, err := a.auditRepo.GetAuditEvents(ctx, filters, from, to, limit, offset)
	if err != nil {
		a.logger.Error(a.module, requestID, "[GetAuditEvents]: An error occurred retrieving audit events: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve audit events")
	}

	return events, nil
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
	const limit int = 1000
	const offset int = 0

	events, err := a.auditRepo.GetAuditEvents(ctx, map[string]any{}, time.Time{}, olderThan, limit, offset)
	if err != nil {
		a.logger.Error(a.module, "", "[DeleteOldEvents]: An error retrieving old audit events: %v", err)
		return errors.Wrap(err, "", "failed to retrieve old audit events")
	}

	if len(events) == 0 {
		a.logger.Info(a.module, "", "[DeleteOldEvents]: No audit events to remove in the given time period")
		return nil
	}

	for _, event := range events {
		if err := a.auditRepo.DeleteEvent(ctx, event.EventID); err != nil {
			a.logger.Error(a.module, "", "[DeleteOldEvents]: An error occurred deleting event ID=[%s]: %v", event.EventID, err)
			return errors.Wrap(err, "", "failed to delete audit event")
		}
	}

	return nil
}
