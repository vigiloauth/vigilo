package service

import (
	"context"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	cookie "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ session.SessionManager = (*sessionManager)(nil)

type sessionManager struct {
	repo    session.SessionRepository
	cookies cookie.HTTPCookieService

	logger *config.Logger
	module string
}

func NewSessionManager(
	repo session.SessionRepository,
	cookies cookie.HTTPCookieService,
) session.SessionManager {
	return &sessionManager{
		repo:    repo,
		cookies: cookies,
		logger:  config.GetServerConfig().Logger(),
		module:  "Session Manager",
	}
}

// GetUserIDFromSession checks if the user session is active based on the provided context and HTTP request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - r *http.Request: The HTTP request associated with the user session.
//
// Returns:
//   - string: The user ID if the session is active, or an empty string if not.
//   - error: An error if the session data retrieval fails.
func (s *sessionManager) GetUserIDFromSession(ctx context.Context, r *http.Request) (string, error) {
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.cookies.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve session cookie from header: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	sessionData, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve user ID from session: %v", err)
		return "", errors.Wrap(err, "", "failed to retrieve session")
	}

	return sessionData.UserID, nil
}

// GetUserAuthenticationTime retrieves the authentication time of the user session based on the provided context and HTTP request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - r *http.Request: The HTTP request associated with the user session.
//
// Returns:
//   - int64: The authentication time in Unix timestamp format.
//   - error: An error if the session data retrieval fails.
func (s *sessionManager) GetUserAuthenticationTime(ctx context.Context, r *http.Request) (int64, error) {
	requestID := utils.GetRequestID(ctx)

	cookie, err := s.cookies.GetSessionCookie(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session cookie from header: %v", err)
		return int64(0), errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}

	sessionID := cookie.Value
	sessionData, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session by ID: %v", err)
		return int64(0), errors.Wrap(err, "", "failed to retrieve session")
	}

	return sessionData.AuthenticationTime.UTC().Unix(), nil
}
