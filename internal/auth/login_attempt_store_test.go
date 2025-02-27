package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func TestNewLoginAttempt(t *testing.T) {
	ipAddress := utils.TestConstants.IPAddress
	requestMetadata := utils.TestConstants.RequestMetadata
	details := utils.TestConstants.Details
	userAgent := utils.TestConstants.UserAgent

	attempt := NewLoginAttempt(ipAddress, requestMetadata, details, userAgent)

	assert.Equal(t, ipAddress, attempt.IPAddress)
	assert.Equal(t, requestMetadata, attempt.RequestMetadata)
	assert.Equal(t, details, attempt.Details)
	assert.Equal(t, userAgent, attempt.UserAgent)
	assert.WithinDuration(t, time.Now(), attempt.Timestamp, time.Second)
}

func TestLogLoginAttempt(t *testing.T) {
	store := NewLoginAttemptStore()
	userID := "user1"
	attempt := &LoginAttempt{
		UserID:          userID,
		IPAddress:       utils.TestConstants.IPAddress,
		Timestamp:       time.Now(),
		RequestMetadata: utils.TestConstants.RequestMetadata,
		Details:         utils.TestConstants.Details,
		UserAgent:       utils.TestConstants.UserAgent,
	}

	store.LogLoginAttempt(attempt)

	attempts := store.GetLoginAttempts(userID)
	assert.Equal(t, 1, len(attempts))
	assert.Equal(t, attempt, attempts[0])
}

func TestGetLoginAttempts(t *testing.T) {
	store := NewLoginAttemptStore()
	userID := "user1"
	attempt1 := &LoginAttempt{
		UserID:          userID,
		IPAddress:       "192.168.1.1",
		Timestamp:       time.Now(),
		RequestMetadata: "metadata1",
		Details:         "details1",
		UserAgent:       "user-agent1",
	}
	attempt2 := &LoginAttempt{
		UserID:          userID,
		IPAddress:       "192.168.1.2",
		Timestamp:       time.Now(),
		RequestMetadata: "metadata2",
		Details:         "details2",
		UserAgent:       "user-agent2",
	}

	store.LogLoginAttempt(attempt1)
	store.LogLoginAttempt(attempt2)

	attempts := store.GetLoginAttempts(userID)
	assert.Equal(t, 2, len(attempts))
	assert.Equal(t, attempt1, attempts[0])
	assert.Equal(t, attempt2, attempts[1])
}
