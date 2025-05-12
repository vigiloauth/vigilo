package service

import (
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	cookie "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

// Ensure SessionService implements the Session interface.
var _ session.SessionService = (*sessionService)(nil)

// sessionService handles session management.
type sessionService struct {
	sessionRepo       session.SessionRepository
	httpCookieService cookie.HTTPCookieService
	auditLogger       audit.AuditLogger
	sessionDuration   time.Duration
	logger            *config.Logger
	module            string
}

// NewSessionService creates a new instance of SessionService with the required dependencies.
//
// Parameters:
//   - sessionRepo SessionRepository: The session repository.
//   - httpCookieService HTTPCookieService: The HTTP Cookie Service instance.
//   - auditLogger AuditLogger: The Audit Logger instance.
//
// Returns:
//   - *SessionService: A new SessionService instance.
func NewSessionService(
	sessionRepo session.SessionRepository,
	httpCookieService cookie.HTTPCookieService,
	auditLogger audit.AuditLogger,
) session.SessionService {
	return &sessionService{
		sessionRepo:       sessionRepo,
		httpCookieService: httpCookieService,
		auditLogger:       auditLogger,
		logger:            config.GetServerConfig().Logger(),
		sessionDuration:   config.GetServerConfig().TokenConfig().ExpirationTime(),
		module:            "Session Service",
	}
}

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
//
// Parameters:
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//   - userID string: The user's ID address.
//   - sessionExpiration time.Duration: The session expiration time.
//
// Returns:
//   - error: An error if token generation or cookie setting fails.
func (s *sessionService) CreateSession(w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) error {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	sessionData.ID = constants.SessionIDPrefix + crypto.GenerateUUID()
	sessionData.ExpirationTime = time.Now().Add(s.sessionDuration)

	if err := s.sessionRepo.SaveSession(ctx, sessionData); err != nil {
		s.logger.Error(s.module, requestID, "[CreateSession]: Failed to save session: %v", err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "error creating session")
		s.auditLogger.StoreEvent(ctx, audit.SessionCreated, false, audit.SessionCreationAction, audit.CookieMethod, wrappedErr)
		return wrappedErr
	}

	s.auditLogger.StoreEvent(ctx, audit.SessionCreated, true, audit.SessionCreationAction, audit.CookieMethod, nil)
	s.httpCookieService.SetSessionCookie(ctx, w, sessionData.ID, s.sessionDuration)
	return nil
}

// InvalidateSession invalidates the session token by adding it to the blacklist.
//
// Parameters:
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//
// Returns:
//   - error: An error if token parsing or blacklist addition fails.
func (s *sessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.httpCookieService.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[InvalidSession]: Failed to retrieve session cookie from header: %v", err)
		return errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	if err := s.sessionRepo.DeleteSessionByID(ctx, sessionID); err != nil {
		s.logger.Error(s.module, requestID, "[InvalidateSession]: Failed to delete session=[%s]: %v", utils.TruncateSensitive(sessionID), err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate session")
		s.auditLogger.StoreEvent(ctx, audit.SessionDeleted, false, audit.SessionDeletionAction, audit.CookieMethod, wrappedErr)
		return wrappedErr
	}

	s.httpCookieService.ClearSessionCookie(ctx, w)
	s.auditLogger.StoreEvent(ctx, audit.SessionDeleted, true, audit.SessionDeletionAction, audit.CookieMethod, nil)
	return nil
}

// GetUserIDFromSession retrieves the user ID from the current session.
//
// Parameters:
//   - r *http.Request: The HTTP request.
//
// Returns:
//   - string: The user ID.
func (s *sessionService) GetUserIDFromSession(r *http.Request) (string, error) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.httpCookieService.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve session cookie from header: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	sessionData, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve user ID from session: %v", err)
		return "", errors.Wrap(err, "", "failed to retrieve user ID from session")
	}

	return sessionData.UserID, nil
}

// UpdateSession updates the current session.
//
// Parameters:
//   - r *http.Request: The HTTP request.
//   - sessionData *SessionData: The sessionData to update.
//
// Returns:
//   - error: If an error occurs during the update.
func (s *sessionService) UpdateSession(r *http.Request, sessionData *session.SessionData) error {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.httpCookieService.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[UpdateSession]: Failed to retrieve session cookie from header: %v", err)
		return errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	if sessionID != sessionData.ID {
		s.logger.Error(s.module, requestID, "[UpdateSession]: SessionID=[%s] and SessionDataID=[%s] do not match",
			utils.TruncateSensitive(sessionID),
			utils.TruncateSensitive(sessionData.ID),
		)
		return errors.New(errors.ErrCodeUnauthorized, "session IDs do no match")
	}

	if err := s.sessionRepo.UpdateSessionByID(ctx, sessionID, sessionData); err != nil {
		s.logger.Error(s.module, requestID, "[UpdateSession]: Failed to update session: %v", err)
		return errors.Wrap(err, "", "failed to update session")
	}

	return nil
}

// GetSessionData retrieves the current session.
//
// Parameters:
//   - r *http.Request: The HTTP request.
//
// Returns:
//   - *SessionData: The session data is successful.
//   - error: An error if retrieval fails.
func (s *sessionService) GetSessionData(r *http.Request) (*session.SessionData, error) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.httpCookieService.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session cookie from header: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	sessionData, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session by ID: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve session")
	}

	return sessionData, nil
}
