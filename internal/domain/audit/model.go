package domain

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
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
	ErrCode   string          `json:"error_code,omitempty"`
}

type EventType string
type ActionType string
type MethodType string

const (
	LoginAttempt        EventType = "login_attempt"
	PasswordChange      EventType = "password_reset"
	RegistrationAttempt EventType = "registration_attempt"
	AccountDeletion     EventType = "account_deletion_attempt"
	SessionCreated      EventType = "session_created"
	SessionDeleted      EventType = "session_deleted"

	RegistrationAction ActionType = "registration"

	AuthenticationAction  ActionType = "authentication"
	PasswordResetAction   ActionType = "password_reset"
	AccountDeletionAction ActionType = "deletion"
	SessionCreationAction ActionType = "session_creation"
	SessionDeletionAction ActionType = "session_deletion"

	EmailMethod  MethodType = "email"
	OAuthMethod  MethodType = "oauth"
	IDMethod     MethodType = "id"
	CookieMethod MethodType = "cookie"
)

func (e EventType) String() string  { return string(e) }
func (a ActionType) String() string { return string(a) }
func (m MethodType) String() string { return string(m) }

func NewAuditEvent(ctx context.Context, eventType EventType, success bool, action ActionType, method MethodType, errCode string) *AuditEvent {
	event := &AuditEvent{
		EventID:   common.AuditEventIDPrefix + crypto.GenerateUUID(),
		Timestamp: time.Now(),
		EventType: eventType,
		Success:   success,
		UserID:    common.GetValueFromContext(ctx, common.ContextKeyUserID),
		IP:        common.GetValueFromContext(ctx, common.ContextKeyIPAddress),
		UserAgent: common.GetValueFromContext(ctx, common.ContextKeyUserAgent),
		RequestID: common.GetRequestID(ctx),
		SessionID: common.GetValueFromContext(ctx, common.ContextKeySessionID),
		ErrCode:   errCode,
	}

	event.addEventDetails(action, method)
	return event
}

func (e *AuditEvent) addEventDetails(action ActionType, method MethodType) {
	details := map[string]string{}
	if action != "" {
		details[common.ActionDetails] = action.String()
	}
	if method != "" {
		details[common.MethodDetails] = method.String()
	}

	JSONDetails, err := json.Marshal(details)
	if err == nil {
		e.Details = JSONDetails
	}
}

func (e *AuditEvent) String() string {
	eventJSON, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "AuditEvent: error serializing to string"
	}
	return string(eventJSON)
}
