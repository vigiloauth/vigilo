package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testIPAddress       string = "127.001.00"
	testRequestMetadata string = "request_metadata"
	testUserAgent       string = "user_agent"
	testRequestDetails  string = "request_details"
)

func TestNewLoginAttempt(t *testing.T) {
	attempt := NewLoginAttempt(testIPAddress, testRequestMetadata, testRequestDetails, testUserAgent)

	assert.Equal(t, testIPAddress, attempt.IPAddress)
	assert.Equal(t, testRequestMetadata, attempt.RequestMetadata)
	assert.Equal(t, testRequestDetails, attempt.Details)
	assert.Equal(t, testUserAgent, attempt.UserAgent)
	assert.WithinDuration(t, time.Now(), attempt.Timestamp, time.Second)
}

func TestLogLoginAttempt(t *testing.T) {
	store := NewInMemoryLoginAttemptStore()
	userID := "user1"
	attempt := &LoginAttempt{
		UserID:          userID,
		IPAddress:       testIPAddress,
		Timestamp:       time.Now(),
		RequestMetadata: testRequestMetadata,
		Details:         testRequestDetails,
		UserAgent:       testUserAgent,
	}

	store.SaveLoginAttempt(attempt)

	attempts := store.GetLoginAttempts(userID)
	assert.Equal(t, 1, len(attempts))
	assert.Equal(t, attempt, attempts[0])
}

func TestGetLoginAttempts(t *testing.T) {
	store := NewInMemoryLoginAttemptStore()
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

	store.SaveLoginAttempt(attempt1)
	store.SaveLoginAttempt(attempt2)

	attempts := store.GetLoginAttempts(userID)
	assert.Equal(t, 2, len(attempts))
	assert.Equal(t, attempt1, attempts[0])
	assert.Equal(t, attempt2, attempts[1])
}
