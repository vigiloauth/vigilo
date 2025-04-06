package repository

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const (
	testSessionID string = "sessionID"
	testUserID    string = "user_id"
)

func setup() {
	config.GetServerConfig().Logger().SetLevel("DEBUG")
}

func tearDown() {
	config.GetServerConfig().Logger().SetLevel("INFO")
}

func TestInMemorySessionRepository_SaveSession(t *testing.T) {
	setup()
	defer tearDown()

	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		err := sessionRepo.SaveSession(sessionData)
		assert.NoError(t, err)

		existingSession, err := sessionRepo.GetSessionByID(testSessionID)
		assert.NoError(t, err)
		assert.NotNil(t, existingSession)
		assert.Equal(t, testSessionID, existingSession.ID)
	})

	t.Run("Error is returned for duplicate entries", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Add entry
		err := sessionRepo.SaveSession(sessionData)
		assert.NoError(t, err)

		// Add duplicate entry
		expected := errors.New(errors.ErrCodeDuplicateSession, "session already exists with the given ID")
		actual := sessionRepo.SaveSession(sessionData)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})
}

func TestInMemorySessionRepository_GetSessionByID(t *testing.T) {
	setup()
	defer tearDown()

	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Save session
		err := sessionRepo.SaveSession(sessionData)
		assert.NoError(t, err)

		// Assert session is present in repository
		existingSession, err := sessionRepo.GetSessionByID(testSessionID)
		assert.NoError(t, err)
		assert.NotNil(t, existingSession)
	})

	t.Run("Returns nil when no session exists", func(t *testing.T) {
		sessionRepo := NewInMemorySessionRepository()
		existingSession, err := sessionRepo.GetSessionByID(testSessionID)
		assert.NoError(t, err)
		assert.Nil(t, existingSession)
	})
}

func TestInMemorySessionRepository_UpdateSessionByID(t *testing.T) {
	setup()
	defer tearDown()

	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Save session
		err := sessionRepo.SaveSession(sessionData)
		assert.NoError(t, err)

		// Update sessionData
		newUserID := "user_id_1"
		sessionData.UserID = newUserID

		err = sessionRepo.UpdateSessionByID(testSessionID, sessionData)
		assert.NoError(t, err)

		updatedSession, err := sessionRepo.GetSessionByID(testSessionID)
		assert.NoError(t, err)
		assert.Equal(t, newUserID, updatedSession.UserID)
	})

	t.Run("Error is returned when session does not exist by ID", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		expected := errors.New(errors.ErrCodeSessionNotFound, "session does not exist with the provided ID")
		actual := sessionRepo.UpdateSessionByID(testSessionID, sessionData)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})
}

func TestInMemorySessionRepository_DeleteSessionByID(t *testing.T) {
	setup()
	defer tearDown()

	sessionData := getTestSessionData()
	sessionRepo := NewInMemorySessionRepository()

	// Save session
	err := sessionRepo.SaveSession(sessionData)
	assert.NoError(t, err)

	err = sessionRepo.DeleteSessionByID(testSessionID)
	assert.NoError(t, err)

	// Assert the session is deleted
	deletedSession, _ := sessionRepo.GetSessionByID(testSessionID)
	assert.Nil(t, deletedSession)
}

func TestInMemorySessionRepository_CleanupExpiredSessions(t *testing.T) {
	setup()
	defer tearDown()

	t.Run("Removes expired sessions", func(t *testing.T) {
		sessionRepo := NewInMemorySessionRepository()

		// Create three sessions
		expiredSession1 := &session.SessionData{
			ID:             "expired1",
			UserID:         "user1",
			ExpirationTime: time.Now().Add(-5 * time.Minute),
		}
		expiredSession2 := &session.SessionData{
			ID:             "expired2",
			UserID:         "user2",
			ExpirationTime: time.Now().Add(-10 * time.Minute),
		}
		activeSession := &session.SessionData{
			ID:             "active",
			UserID:         "user3",
			ExpirationTime: time.Now().Add(1 * time.Hour),
		}

		// Save sessions
		err := sessionRepo.SaveSession(expiredSession1)
		assert.NoError(t, err)
		err = sessionRepo.SaveSession(expiredSession2)
		assert.NoError(t, err)
		err = sessionRepo.SaveSession(activeSession)
		assert.NoError(t, err)

		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		done := make(chan struct{})
		go func() {
			sessionRepo.CleanupExpiredSessions(ticker)
			close(done)
		}()

		time.Sleep(50 * time.Millisecond)

		session1, err := sessionRepo.GetSessionByID("expired1")
		assert.NoError(t, err)
		assert.Nil(t, session1)

		session2, err := sessionRepo.GetSessionByID("expired2")
		assert.NoError(t, err)
		assert.Nil(t, session2)

		activeSessionCheck, err := sessionRepo.GetSessionByID("active")
		assert.NoError(t, err)
		assert.NotNil(t, activeSessionCheck)
	})

	t.Run("Does nothing when no sessions are expired", func(t *testing.T) {
		sessionRepo := NewInMemorySessionRepository()
		activeSession := &session.SessionData{
			ID:             "active",
			UserID:         "user1",
			ExpirationTime: time.Now().Add(1 * time.Hour),
		}

		err := sessionRepo.SaveSession(activeSession)
		assert.NoError(t, err)

		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		done := make(chan struct{})
		go func() {
			sessionRepo.CleanupExpiredSessions(ticker)
			close(done)
		}()

		time.Sleep(50 * time.Millisecond)

		activeSessionCheck, err := sessionRepo.GetSessionByID("active")
		assert.NoError(t, err)
		assert.NotNil(t, activeSessionCheck)
	})
}

func getTestSessionData() *session.SessionData {
	return &session.SessionData{
		ID:             testSessionID,
		UserID:         testUserID,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
}
