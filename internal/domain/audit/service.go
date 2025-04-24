package domain

import (
	"context"
	"time"
)

type AuditLogger interface {
	// StoreEvent saves an AuditEvent to the repository.
	// If an error occurs storing the audit event, no error will be returned so that the flow is not disrupted.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts, cancellations, and for storing/retrieving event metadata.
	//	- eventType EventType: The type of event to store.
	//	- success bool: True if the event was successful, otherwise false.
	//	- action ActionType: The action that is to be audited.
	//	- method MethodType: The method used (password, email, etc).
	//	- err error: The error if applicable, otherwise nil.
	StoreEvent(ctx context.Context, eventType EventType, success bool, action ActionType, method MethodType, err error)

	// DeleteOldEvents deletes audit events older than the specified timestamp.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - olderThan time.Time: Events older than this timestamp will be deleted.
	//
	// Returns:
	//  - error: An error if deletion fails, otherwise nil.
	DeleteOldEvents(ctx context.Context, olderThan time.Time) error

	// GetAuditEvents retrieves audit events that match the provided filters and time range.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - filters map[string]any: A map of filter keys and values to apply.
	//  - from string: The start time of the time range to filter events (must be RFC3339 Format).
	//  - to string: The end time of the time range to filter events (must be RFC3339 Format).
	//  - limit int: The maximum number of events to return.
	//  - offset int: The number of events to skip (for pagination).
	//
	// Returns:
	//  - []*AuditEvent: A slice of matching audit events.
	//  - error: An error if the retrieval fails, otherwise nil.
	GetAuditEvents(ctx context.Context, filters map[string]any, fromStr string, toStr string, limit, offset int) ([]*AuditEvent, error)
}
