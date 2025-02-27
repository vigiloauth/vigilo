package auth

import (
	"sync"
	"time"
)

const maxStoredLoginAttempts = 100

type LoginAttempt struct {
	UserID          string
	IPAddress       string
	Timestamp       time.Time
	RequestMetadata string
	Details         string
	UserAgent       string
	FailedAttempts  int
}

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

// SaveLoginAttempt logs a login attempt
func (s *LoginAttemptStore) SaveLoginAttempt(attempt *LoginAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.attempts[attempt.UserID] = append(s.attempts[attempt.UserID], attempt)
	s.trimLoginAttempts(attempt.UserID)
}

// GetLoginAttempts returns all login attempts for a given user
func (s *LoginAttemptStore) GetLoginAttempts(userID string) []*LoginAttempt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.attempts[userID]
}

func (s *LoginAttemptStore) trimLoginAttempts(userID string) {
	if len(s.attempts[userID]) > maxStoredLoginAttempts {
		s.attempts[userID] = s.attempts[userID][1:]
	}
}
