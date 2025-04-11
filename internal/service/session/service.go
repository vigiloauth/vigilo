package service

import (
	"net/http"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	cookie "github.com/vigiloauth/vigilo/internal/domain/cookies"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensure SessionService implements the Session interface.
var _ session.SessionService = (*sessionService)(nil)
var logger = config.GetServerConfig().Logger()

const module = "Session Service"

// sessionService handles session management.
type sessionService struct {
	tokenService      token.TokenService
	sessionRepo       session.SessionRepository
	httpCookieService cookie.HTTPCookieService
}

// NewSessionService creates a new instance of SessionService with the required dependencies.
//
// Parameters:
//
//	tokenService TokenService: The token service.
//	sessionRepo SessionRepository: The session repository.
//
// Returns:
//
//	*SessionService: A new SessionService instance.
func NewSessionService(
	tokenService token.TokenService,
	sessionRepo session.SessionRepository,
	httpCookieService cookie.HTTPCookieService,
) session.SessionService {
	return &sessionService{
		tokenService:      tokenService,
		sessionRepo:       sessionRepo,
		httpCookieService: httpCookieService,
	}
}

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
//
// Parameters:
//
//	w http.ResponseWriter: The HTTP response writer.
//	userID string: The user's ID.
//	sessionExpiration time.Duration: The session expiration time.
//
// Returns:
//
//	error: An error if token generation or cookie setting fails.
func (s *sessionService) CreateSession(w http.ResponseWriter, r *http.Request, userID string, sessionExpiration time.Duration) error {
	sessionToken, err := s.tokenService.GenerateToken(userID, "", sessionExpiration)
	if err != nil {
		logger.Error(module, "CreateSession: Failed to generate session token for user=[%s]: %v", common.TruncateSensitive(userID), err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate session token")
	}

	sessionData := &session.SessionData{
		ID:                 sessionToken,
		UserID:             userID,
		UserIPAddress:      r.RemoteAddr,
		UserAgent:          r.UserAgent(),
		ExpirationTime:     time.Now().Add(sessionExpiration),
		AuthenticationTime: time.Now(),
	}

	if err := s.sessionRepo.SaveSession(sessionData); err != nil {
		logger.Error(module, "CreateSession: Failed to save session: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "error creating session")
	}

	s.httpCookieService.SetSessionCookie(w, sessionToken, sessionExpiration)
	logger.Info(module, "CreateSession: Session for user=[%s] created and saved successfully", common.TruncateSensitive(userID))
	return nil
}

// InvalidateSession invalidates the session token by adding it to the blacklist.
//
// Parameters:
//
//	w http.ResponseWriter: The HTTP response writer.
//	r *http.Request: The HTTP request.
//
// Returns:
//
//	error: An error if token parsing or blacklist addition fails.
func (s *sessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	tokenString, err := s.parseTokenFromAuthzHeader(r)
	if tokenString == "" || err != nil {
		logger.Error(module, "InvalidateSession: Failed to invalidate session url=[%s]: %v", common.SanitizeURL(r.URL.String()), err)
		return errors.Wrap(err, "", "failed to parse token from request headers")
	}

	claims, err := s.generateStandardClaims(tokenString)
	if err != nil {
		logger.Error(module, "InvalidateSession: Failed to invalidate session url=[%s]: %v", common.SanitizeURL(r.URL.String()), err)
		return errors.Wrap(err, "", "failed to generate JWT Standard Claims")
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	if expiration.After(time.Now()) {
		s.tokenService.BlacklistToken(tokenString)
	}

	sessionID := claims.Subject
	if err := s.sessionRepo.DeleteSessionByID(sessionID); err != nil {
		logger.Error(module, "InvalidateSession: Failed to delete session=[%s]: %v", common.TruncateSensitive(sessionID), err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate session")
	}

	s.httpCookieService.ClearSessionCookie(w)
	logger.Info(module, "InvalidateSession: Session successfully invalidated")
	return nil
}

// GetUserIDFromSession retrieves the user ID from the current session.
//
// Parameters:
//
//	r *http.Request: The HTTP request.
//
// Returns:
//
//	string: The user ID.
//	error: An error if retrieving the user ID fails.
func (s *sessionService) GetUserIDFromSession(r *http.Request) string {
	tokenString, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
		logger.Error(module, "GetUserIDFromSession: Failed to retrieve user ID: %v", err)
		return ""
	}

	claims, err := s.tokenService.ParseToken(tokenString)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to parse session token")
		logger.Error(module, "GetUserIDFromSession: Failed to retrieve user ID: %v", err)
		return ""
	}

	return claims.Subject
}

// UpdateSession updates the current session.
//
// Parameters:
//
//	r *http.Request: The HTTP request.
//	sessionData SessionData: The sessionData to update.
//
// Returns:
//
//	error: If an error occurs during the update.
func (s *sessionService) UpdateSession(r *http.Request, sessionData *session.SessionData) error {
	sessionID, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		logger.Error(module, "UpdateSession: Failed to retrieve session ID: %v", err)
		return errors.Wrap(err, "", "failed to retrieve session ID")
	}

	if sessionID != sessionData.ID {
		logger.Error(module, "UpdateSession: SessionID=[%s] and SessionDataID=[%s] do not match",
			common.TruncateSensitive(sessionID),
			common.TruncateSensitive(sessionData.ID),
		)
		return errors.New(errors.ErrCodeUnauthorized, "session IDs do no match")
	}

	if err := s.sessionRepo.UpdateSessionByID(sessionID, sessionData); err != nil {
		logger.Error(module, "UpdateSession: Failed to update session=[%s]: %v", common.TruncateSensitive(sessionID), err)
		return errors.Wrap(err, "", "failed to update session")
	}

	logger.Info(module, "UpdateSession: Session=[%s] updated successfully", common.TruncateSensitive(sessionID))
	return nil
}

// GetSessionData retrieves the current session.
//
// Parameters:
//
//	r *http.Request: The HTTP request.
//
// Returns:
//
//	*SessionData: The session data is successful.
//	error: An error if retrieval fails.
func (s *sessionService) GetSessionData(r *http.Request) (*session.SessionData, error) {
	sessionID, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		logger.Error(module, "GetSessionData: Failed to retrieve session data: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve session data")
	}

	sessionData, err := s.sessionRepo.GetSessionByID(sessionID)
	if err != nil {
		logger.Error(module, "GetSessionData: Failed to retrieve session by ID=[%s]: %v", common.TruncateSensitive(sessionID), err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to retrieve session from repository")
	}

	return sessionData, nil
}

// ClearStateFromSession clears the state value from the session data.
//
// Parameters:
//
//	sessionData *SessionData: The session data to be updated.
//
// Returns:
//
//	error: An error if the session update fails, or nil if successful.
func (s *sessionService) ClearStateFromSession(sessionData *session.SessionData) error {
	sessionData.State = ""
	if err := s.sessionRepo.UpdateSessionByID(sessionData.ID, sessionData); err != nil {
		logger.Error(module, "UpdateSession: Failed to update session=[%s]: %v", common.TruncateSensitive(sessionData.ID), err)
		return errors.Wrap(err, "", "failed to update session")
	}

	logger.Info(module, "ClearStateFromSession: State successfully cleared from session=[%s]", common.TruncateSensitive(sessionData.ID))
	return nil
}

// ValidateSessionState retrieves session data and verifies that the state parameter in the request matches the stored session state.
//
// Parameters:
//
//	r *http.Request: The HTTP request containing the session information.
//
// Returns:
//
//	*SessionData: The retrieved session data if validation is successful.
//	error: An error if retrieving session data fails or if the state parameter does not match.
func (s *sessionService) ValidateSessionState(r *http.Request) (*session.SessionData, error) {
	sessionData, err := s.GetSessionData(r)
	if err != nil {
		logger.Error(module, "ValidateSessionState: Failed to retrieve session data: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve session data")
	}

	state := r.URL.Query().Get(common.State)
	if state == "" || state != sessionData.State {
		logger.Error(module, "ValidateSessionData: State parameter=[%s] does not match with session state=[%s]",
			common.TruncateSensitive(state),
			common.TruncateSensitive(sessionData.State),
		)
		return nil, errors.New(errors.ErrCodeInvalidRequest, "state parameter does not match with session state")
	}

	logger.Info(module, "ValidateSessionData: Session data successfully validated")
	return sessionData, nil
}

// parseTokenFromAuthzHeader parses the token from the Authorization header.
//
// Parameters:
//
//	r *http.Request: The HTTP request.
//
// Returns:
//
//	string: The token string.
//	error: An error if the token is invalid or missing.
func (s *sessionService) parseTokenFromAuthzHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get(common.Authorization)
	if authHeader == "" {
		err := errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
		logger.Error(module, "Failed to parse token from authorization header: %v", err)
		return "", err
	}

	token := strings.TrimPrefix(authHeader, common.BearerAuthHeader)
	if token == authHeader {
		err := errors.New(errors.ErrCodeInvalidFormat, "malformed authorization header")
		logger.Error(module, "Failed to parse token from authorization header: %v", err)
		return "", err
	}

	return token, nil
}

// generateStandardClaims parses the token and returns the standard claims.
//
// Parameters:
//
//	token string: The token string.
//
// Returns:
//
//	*jwt.StandardClaims: The standard claims.
//	error: An error if token parsing fails.
func (s *sessionService) generateStandardClaims(token string) (*token.TokenClaims, error) {
	claims, err := s.tokenService.ParseToken(token)
	if err != nil {
		logger.Error(module, "Failed to generate token with standard claims: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse token")
	}

	return claims, nil
}
