package auth

import (
	"sync"
	"time"
)

var _ LoginAttemptStore = (*InMemoryLoginAttemptStore)(nil)

func NewLoginAttempt(ipAddress, requestMetadata, details, userAgent string) *LoginAttempt {
	return &LoginAttempt{
		IPAddress:       ipAddress,
		Timestamp:       time.Now(),
		RequestMetadata: requestMetadata,
		Details:         details,
		UserAgent:       userAgent,
		FailedAttempts:  0,
	}
}

// InMemoryLoginAttemptStore is a store for login attempts
type InMemoryLoginAttemptStore struct {
	attempts map[string][]*LoginAttempt
	mu       sync.RWMutex
}

// NewInMemoryLoginAttemptStore creates a new LoginAttemptStore
func NewInMemoryLoginAttemptStore() *InMemoryLoginAttemptStore {
	return &InMemoryLoginAttemptStore{
		attempts: make(map[string][]*LoginAttempt),
	}
}

// SaveLoginAttempt logs a login attempt
func (s *InMemoryLoginAttemptStore) SaveLoginAttempt(attempt *LoginAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	s.trimLoginAttempts(attempt.UserID)
}

// GetLoginAttempts returns all login attempts for a given user
func (s *InMemoryLoginAttemptStore) GetLoginAttempts(userID string) []*LoginAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.attempts[userID]
}

func (s *InMemoryLoginAttemptStore) trimLoginAttempts(userID string) {
	if len(s.attempts[userID]) > maxStoredLoginAttempts {
		s.attempts[userID] = s.attempts[userID][1:]
	}
}
