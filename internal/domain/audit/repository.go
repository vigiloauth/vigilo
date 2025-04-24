package domain

import (
	"context"
	"time"
)

// AuditRepository defines the interface for storing and retrieving audit events.
type AuditRepository interface {
	// StoreAuditEvent stores an audit event in the repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - event *AuditEvent: The audit event to be stored.
	//
	// Returns:
	//   - error: An error if storing the event fails, otherwise nil.
	StoreAuditEvent(ctx context.Context, event *AuditEvent) error

	// GetAuditEvents retrieves audit events that match the provided filters and time range.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - filters map[string]any: A map of filter keys and values to apply.
	//  - from time.Time: The start time of the time range to filter events.
	//  - to time.Time: The end time of the time range to filter events.
	//  - limit int: The maximum number of events to return.
	//  - offset int: The number of events to skip (for pagination).
	//
	// Returns:
	//  - []*AuditEvent: A slice of matching audit events.
	//  - error: An error if the retrieval fails, otherwise nil.
	GetAuditEvents(ctx context.Context, filters map[string]any, from time.Time, to time.Time, limit, offset int) ([]*AuditEvent, error)

	// DeleteEvent deletes an event using the given event ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - eventID string: The ID of the event to delete.
	//
	// Returns:
	//  - error: An error if deletion fails, otherwise nil.
	DeleteEvent(ctx context.Context, eventID string) error
}
