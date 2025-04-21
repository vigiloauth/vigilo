package domain

import (
	"encoding/json"
	"time"
)

type AuditEvent struct {
	EventID   string          `json:"event_id"`
	Timestamp time.Time       `json:"timestamp"`
	EventType EventType       `json:"event_type"`
	Success   bool            `json:"success"`
	UserID    string          `json:"user_id,omitempty"`
	IP        string          `json:"ip_address"`
	UserAgent string          `json:"user_agent,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Details   json.RawMessage `json:"details,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
}

type EventType string

const (
	LoginAttempt   EventType = "login_attempt"
	PasswordChange EventType = "password_reset"
)

func (e EventType) String() string {
	return string(e)
}
