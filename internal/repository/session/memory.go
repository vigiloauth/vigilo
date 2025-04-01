package repository

import (
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"

	session "github.com/vigiloauth/vigilo/internal/domain/session"
)

var (
	logger                             = config.GetServerConfig().Logger()
	_        session.SessionRepository = (*InMemorySessionRepository)(nil)
	instance *InMemorySessionRepository
	once     sync.Once
)

const module = "InMemorySessionRepository"

type InMemorySessionRepository struct {
	data map[string]*session.SessionData
	mu   sync.RWMutex
}

func NewInMemorySessionRepository() *InMemorySessionRepository {
	return &InMemorySessionRepository{
		data: make(map[string]*session.SessionData),
	}
}

func GetInMemorySessionRepository() *InMemorySessionRepository {
	once.Do(func() {
		logger.Debug(module, "Creating new instance of InMemorySessionRepository")
		instance = &InMemorySessionRepository{
			data: make(map[string]*session.SessionData),
		}
	})
	return instance
}

func ResetInMemorySessionRepository() {
	if instance != nil {
		logger.Debug(module, "Resetting instance")
		instance.mu.Lock()
		instance.data = make(map[string]*session.SessionData)
		instance.mu.Unlock()
	}
}

// SaveSession creates a new session and returns the session ID.
// Parameters:
//
//   - sessionData SessionData: The data to store in the new session.
//
// Returns:
//
//   - error: An error if the session creation fails.
func (s *InMemorySessionRepository) SaveSession(sessionData *session.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[sessionData.ID]; ok {
		logger.Debug(module, "SaveSession: Failed to save session as it already exists")
		return errors.New(errors.ErrCodeDuplicateSession, "session already exists with the given ID")
	}

	s.data[sessionData.ID] = sessionData
	return nil
}

// GetSessionByID retrieves session data for a given session ID.
// Parameters:
//
//   - sessionID string: The unique identifier of the session to retrieve.
//
// Returns:
//
//   - SessionData: The session data associated with the session ID.
//   - error: An error if the session is not found or retrieval fails.
func (s *InMemorySessionRepository) GetSessionByID(sessionID string) (*session.SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, found := s.data[sessionID]
	if !found {
		logger.Debug(module, "GetSessionByID: No session exists with the given ID=%s", sessionID)
		return nil, nil
	}

	return session, nil
}

// UpdateSessionByID updates the session data for a given session ID.
// Parameters:
//
//   - sessionID string: The unique identifier of the session to update.
//   - sessionData SessionData: The updated session data.
//
// Returns:
//
//   - error: An error if the update fails.
func (s *InMemorySessionRepository) UpdateSessionByID(sessionID string, sessionData *session.SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.data[sessionID]; !ok {
		logger.Debug(module, "UpdateSessionByID: No session exists with the given ID=%s", sessionID)
		return errors.New(errors.ErrCodeSessionNotFound, "session does not exist with the provided ID")
	}

	return nil
}

// DeleteSessionByID removes a session with the given session ID.
// Parameters:
//
//   - sessionID string: The unique identifier of the session to delete.
//
// Returns:
//
//   - error: An error if the deletion fails.
func (s *InMemorySessionRepository) DeleteSessionByID(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sessionID)
	return nil
}

// CleanupExpiredSessions starts a go routine and removes all expired sessions from the repository.
func (s *InMemorySessionRepository) CleanupExpiredSessions(ticker *time.Ticker) {
	logger.Debug(module, "Starting process to cleanup expired sessions")
	go func() {
		defer ticker.Stop()

		for range ticker.C {
			s.mu.Lock()
			now := time.Now()

			expiredSessionIDs := []string{}
			for sessionID, sessionData := range s.data {
				if sessionData.ExpirationTime.Before(now) {
					expiredSessionIDs = append(expiredSessionIDs, sessionID)
				}
			}

			for _, sessionID := range expiredSessionIDs {
				delete(s.data, sessionID)
			}

			s.mu.Unlock()
		}
	}()
	logger.Debug(module, "Finished process to cleanup expired sessions")
}
