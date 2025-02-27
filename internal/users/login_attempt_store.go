package users

import (
	"sync"
	"time"
)

var maxStoredLoginAttempts = 100

type LoginAttempt struct {
	UserID           string
	IPAddress        string
	Timestamp        time.Time
	RequestMetadata  string
	Details          string
	UserAgent        string
	FailedLoginCount int
}

func NewLoginAttempt(ipAddress, requestMetadata, details, userAgent string) *LoginAttempt {
	return &LoginAttempt{
		IPAddress:        ipAddress,
		Timestamp:        time.Now(),
		RequestMetadata:  requestMetadata,
		Details:          details,
		UserAgent:        userAgent,
		FailedLoginCount: 0,
	}
}

// LoginAttemptStore is a store for login attempts
type LoginAttemptStore struct {
	attempts map[string][]*LoginAttempt
	mu       sync.RWMutex
}

// NewLoginAttemptStore creates a new LoginAttemptStore
func NewLoginAttemptStore() *LoginAttemptStore {
	return &LoginAttemptStore{
		attempts: make(map[string][]*LoginAttempt),
	}
}

// LogLoginAttempt logs a login attempt
func (s *LoginAttemptStore) LogLoginAttempt(attempt *LoginAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt.FailedLoginCount++
	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	if len(s.attempts[attempt.UserID]) > maxStoredLoginAttempts {
		s.attempts[attempt.UserID] = s.attempts[attempt.UserID][1:]
	}
}

// GetLoginAttempts returns all login attempts for a given user
func (s *LoginAttemptStore) GetLoginAttempts(userID string) []*LoginAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.attempts[userID]
}
