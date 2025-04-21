package repository

import (
	"context"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
)

var (
	logger   = config.GetServerConfig().Logger()
	instance *InMemoryAuditEventRepository
	once     sync.Once
	_        domain.AuditRepository = (*InMemoryAuditEventRepository)(nil)
)

const module string = "InMemoryAuditEventRepository"

type InMemoryAuditEventRepository struct {
	events map[string]*domain.AuditEvent
	mu     sync.RWMutex
}

// GetInMemoryAuditEventRepository returns the singleton instance of InMemoryAuditEventRepository.
//
// Returns:
//   - *InMemoryAuditEventRepository: The singleton instance of InMemoryAuditEventRepository.
func GetInMemoryAuditEventRepository() *InMemoryAuditEventRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryAuditEventRepository")
		instance = &InMemoryAuditEventRepository{
			events: make(map[string]*domain.AuditEvent),
		}
	})
	return instance
}

// ResetInMemoryAuditEventRepository resets the in-memory audit event store for testing purposes.
func ResetInMemoryAuditEventRepository() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.events = make(map[string]*domain.AuditEvent)
		instance.mu.Unlock()
	}
}

// StoreAuditEvent stores an audit event in the repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - event *AuditEvent: The audit event to be stored.
//
// Returns:
//   - error: An error if storing the event fails, otherwise nil.
func (r *InMemoryAuditEventRepository) StoreAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events[event.EventID] = event
	return nil
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
func (r *InMemoryAuditEventRepository) GetAuditEvents(
	ctx context.Context,
	filters map[string]any,
	from time.Time,
	to time.Time,
	limit int,
	offset int,
) ([]*domain.AuditEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	auditEvents, err := r.getFilteredEvents(ctx, filters, from, to)
	if err != nil {
		logger.Error(module, common.GetRequestID(ctx), "[GetRequestID]: An error occurred retrieving filtered events: %v", err)
		return nil, err
	}

	start := min(offset, len(auditEvents))
	end := min(start+limit, len(auditEvents))

	return auditEvents[start:end], nil
}

// DeleteOldEvents deletes audit events older than the specified timestamp.
//
// DeleteOldEvents scans all stored audit events and removes those with a timestamp
// earlier than the given `olderThan` value.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - olderThan time.Time: Events older than this timestamp will be deleted.
//
// Returns:
//   - error: An error if deletion fails, otherwise nil.
func (r *InMemoryAuditEventRepository) DeleteOldEvents(ctx context.Context, olderThan time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, event := range r.events {
		if event.Timestamp.Before(olderThan) {
			logger.Info(module, common.GetRequestID(ctx), "[DeleteOldEvents]: Deleted event with ID: %s", event.EventID)
			delete(r.events, event.EventID)
		}
	}

	return nil
}

func (r *InMemoryAuditEventRepository) getFilteredEvents(ctx context.Context, filters map[string]any, from time.Time, to time.Time) ([]*domain.AuditEvent, error) {
	var auditEvents []*domain.AuditEvent

loop:
	for _, event := range r.events {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			if event.Timestamp.Before(from) || event.Timestamp.After(to) {
				continue
			}

			for key, value := range filters {
				switch key {
				case "UserID":
					if v, ok := value.(string); !ok || event.UserID != v {
						continue loop
					}
				case "EventType":
					if v, ok := value.(string); !ok || event.EventType.String() != v {
						continue loop
					}
				case "Success":
					if v, ok := value.(bool); !ok || event.Success != v {
						continue loop
					}
				case "IP":
					if v, ok := value.(string); !ok || event.IP != v {
						continue loop
					}
				case "RequestID":
					if v, ok := value.(string); !ok || event.RequestID != v {
						continue loop
					}
				case "SessionID":
					if v, ok := value.(string); !ok || event.SessionID != v {
						continue loop
					}
				default:
					logger.Warn(module, common.GetRequestID(ctx), "[GetAuditEvents]: Unknown filter: %s", key)
					continue loop
				}
			}

			auditEvents = append(auditEvents, event)
		}
	}

	return auditEvents, nil
}
