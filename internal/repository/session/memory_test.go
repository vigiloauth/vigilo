package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const (
	testSessionID string = "sessionID"
	testUserID    string = "user_id"
)

func TestInMemorySessionRepository_SaveSession(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		err := sessionRepo.SaveSession(ctx, sessionData)
		assert.NoError(t, err)

		existingSession, err := sessionRepo.GetSessionByID(ctx, testSessionID)
		assert.NoError(t, err)
		assert.NotNil(t, existingSession)
		assert.Equal(t, testSessionID, existingSession.ID)
	})

	t.Run("Error is returned for duplicate entries", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Add entry
		err := sessionRepo.SaveSession(ctx, sessionData)
		assert.NoError(t, err)

		// Add duplicate entry
		expected := errors.New(errors.ErrCodeDuplicateSession, "session already exists with the given ID")
		actual := sessionRepo.SaveSession(ctx, sessionData)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})
}

func TestInMemorySessionRepository_GetSessionByID(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Save session
		err := sessionRepo.SaveSession(ctx, sessionData)
		assert.NoError(t, err)

		// Assert session is present in repository
		existingSession, err := sessionRepo.GetSessionByID(ctx, testSessionID)
		assert.NoError(t, err)
		assert.NotNil(t, existingSession)
	})

	t.Run("Returns nil when no session exists", func(t *testing.T) {
		sessionRepo := NewInMemorySessionRepository()
		existingSession, err := sessionRepo.GetSessionByID(ctx, testSessionID)
		assert.Error(t, err)
		assert.Nil(t, existingSession)
	})
}

func TestInMemorySessionRepository_UpdateSessionByID(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		// Save session
		err := sessionRepo.SaveSession(ctx, sessionData)
		assert.NoError(t, err)

		// Update sessionData
		newUserID := "user_id_1"
		sessionData.UserID = newUserID

		err = sessionRepo.UpdateSessionByID(ctx, testSessionID, sessionData)
		assert.NoError(t, err)

		updatedSession, err := sessionRepo.GetSessionByID(ctx, testSessionID)
		assert.NoError(t, err)
		assert.Equal(t, newUserID, updatedSession.UserID)
	})

	t.Run("Error is returned when session does not exist by ID", func(t *testing.T) {
		sessionData := getTestSessionData()
		sessionRepo := NewInMemorySessionRepository()

		expected := errors.New(errors.ErrCodeSessionNotFound, "session does not exist with the provided ID")
		actual := sessionRepo.UpdateSessionByID(ctx, testSessionID, sessionData)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})
}

func TestInMemorySessionRepository_DeleteSessionByID(t *testing.T) {
	ctx := context.Background()
	sessionData := getTestSessionData()
	sessionRepo := NewInMemorySessionRepository()

	// Save session
	err := sessionRepo.SaveSession(ctx, sessionData)
	assert.NoError(t, err)

	err = sessionRepo.DeleteSessionByID(ctx, testSessionID)
	assert.NoError(t, err)

	// Assert the session is deleted
	deletedSession, err := sessionRepo.GetSessionByID(ctx, testSessionID)
	assert.Error(t, err)
	assert.Nil(t, deletedSession)
}

func getTestSessionData() *session.SessionData {
	return &session.SessionData{
		ID:             testSessionID,
		UserID:         testUserID,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
}
