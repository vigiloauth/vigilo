package service

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	cookie "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

// Ensure SessionService implements the Session interface.
var _ session.SessionService = (*sessionService)(nil)

// sessionService handles session management.
type sessionService struct {
	tokenService      token.TokenService
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
//   - tokenService TokenService: The token service.
//   - sessionRepo SessionRepository: The session repository.
//   - httpCookieService HTTPCookieService: The HTTP Cookie Service instance.
//
// Returns:
//   - *SessionService: A new SessionService instance.
func NewSessionService(
	tokenService token.TokenService,
	sessionRepo session.SessionRepository,
	httpCookieService cookie.HTTPCookieService,
	auditLogger audit.AuditLogger,
) session.SessionService {
	return &sessionService{
		tokenService:      tokenService,
		sessionRepo:       sessionRepo,
		httpCookieService: httpCookieService,
		auditLogger:       auditLogger,
		logger:            config.GetServerConfig().Logger(),
		sessionDuration:   config.GetServerConfig().TokenConfig().ExpirationTime(),
		module:            "Session Service",
	}
}

// GetOrCreateSession attempts to retrieve an existing session or creates one if it doesn't exist.
//
// Parameters:
//   - ctx context.Context: Context for managing timeouts and request IDs.
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//   - sessionData *SessionData: The session data.
//
// Returns:
//   - *SessionData: The retrieved or created session data.
//   - error: An error if retrieval or creation fails.
func (s *sessionService) GetOrCreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
	requestID := utils.GetRequestID(ctx)

	existingSession, err := s.getExistingSession(ctx, r)
	if err == nil {
		return existingSession, nil
	}

	if vaErr, ok := err.(*errors.VigiloAuthError); ok &&
		vaErr.ErrorCode == errors.ErrCodeSessionNotFound ||
		vaErr.ErrorCode == errors.ErrCodeMissingHeader {
		s.logger.Info(s.module, requestID, "[GetOrCreateSession]: Creating new session because: %v", vaErr.ErrorCode)
	} else {
		s.logger.Error(s.module, requestID, "[GetOrCreateSession]: Failed to retrieve session: %v", err)
		return nil, err
	}

	if err := s.populateNewSession(r, sessionData); err != nil {
		s.logger.Error(s.module, requestID, "[GetOrCreateSession]: Failed to create new session: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeSessionCreation, "failed to create new session")
	}

	if err := s.sessionRepo.SaveSession(ctx, sessionData); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeSessionSave, "failed to save new session")
	}

	token, err := s.tokenService.EncryptToken(ctx, sessionData.ID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenEncryption, "failed to encrypt session token")
	}

	s.httpCookieService.SetSessionCookie(ctx, w, token, s.sessionDuration)
	return sessionData, nil
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

	tokenString, err := s.parseTokenFromAuthzHeader(r)
	if tokenString == "" || err != nil {
		s.logger.Error(s.module, requestID, "[InvalidateSession]: Failed to invalidate session url=[%s]: %v", utils.SanitizeURL(r.URL.String()), err)
		return errors.Wrap(err, "", "failed to parse token from request headers")
	}

	claims, err := s.generateStandardClaims(ctx, tokenString)
	if err != nil {
		s.logger.Error(s.module, requestID, "[InvalidateSession]: Failed to invalidate session url=[%s]: %v", utils.SanitizeURL(r.URL.String()), err)
		return errors.Wrap(err, "", "failed to generate JWT Standard Claims")
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	if expiration.After(time.Now()) {
		s.tokenService.BlacklistToken(ctx, tokenString)
	}

	sessionID := claims.Subject
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
func (s *sessionService) GetUserIDFromSession(r *http.Request) string {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	tokenString, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve user ID: %v", err)
		return ""
	}

	claims, err := s.tokenService.ParseToken(tokenString)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to parse session token")
		s.logger.Error(s.module, requestID, "[GetUserIDFromSession]: Failed to retrieve user ID: %v", err)
		return ""
	}

	return claims.Subject
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

	sessionID, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[UpdateSession]: Failed to retrieve session ID: %v", err)
		return errors.Wrap(err, "", "failed to retrieve session ID")
	}

	if sessionID != sessionData.ID {
		s.logger.Error(s.module, requestID, "[UpdateSession]: SessionID=[%s] and SessionDataID=[%s] do not match",
			utils.TruncateSensitive(sessionID),
			utils.TruncateSensitive(sessionData.ID),
		)
		return errors.New(errors.ErrCodeUnauthorized, "session IDs do no match")
	}

	if err := s.sessionRepo.UpdateSessionByID(ctx, sessionID, sessionData); err != nil {
		s.logger.Error(s.module, requestID, "[UpdateSession]: Failed to update session=[%s]: %v", utils.TruncateSensitive(sessionID), err)
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

	sessionID, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session data: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve session data")
	}

	sessionData, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetSessionData]: Failed to retrieve session by ID=[%s]: %v", utils.TruncateSensitive(sessionID), err)
		return nil, errors.Wrap(err, "", "failed to retrieve session")
	}

	return sessionData, nil
}

func (s *sessionService) parseTokenFromAuthzHeader(r *http.Request) (string, error) {
	requestID := utils.GetRequestID(r.Context())
	authHeader := r.Header.Get(constants.AuthorizationHeader)
	if authHeader == "" {
		err := errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
		s.logger.Error(s.module, requestID, "Failed to parse token from authorization header: %v", err)
		return "", err
	}

	token := strings.TrimPrefix(authHeader, constants.BearerAuthHeader)
	if token == authHeader {
		err := errors.New(errors.ErrCodeInvalidFormat, "malformed authorization header")
		s.logger.Error(s.module, requestID, "Failed to parse token from authorization header: %v", err)
		return "", err
	}

	return token, nil
}

func (s *sessionService) generateStandardClaims(ctx context.Context, token string) (*token.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)
	claims, err := s.tokenService.ParseToken(token)
	if err != nil {
		s.logger.Error(s.module, requestID, "Failed to generate token with standard claims: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse token")
	}

	return claims, nil
}

func (s *sessionService) populateNewSession(r *http.Request, sessionData *session.SessionData) error {
	sessionID, err := crypto.GenerateRandomString(32)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate session ID")
	}

	ipAddr := r.Header.Get(constants.XForwardedHeader)
	if ipAddr == "" {
		ipAddr = r.RemoteAddr
	}

	sessionData.ID = constants.SessionIDPrefix + sessionID
	sessionData.IPAddress = ipAddr
	sessionData.UserAgent = r.UserAgent()
	sessionData.ExpirationTime = time.Now().Add(s.sessionDuration)
	sessionData.AuthenticationTime = time.Time{}

	return nil
}

func (s *sessionService) getExistingSession(ctx context.Context, r *http.Request) (*session.SessionData, error) {
	requestID := utils.GetRequestID(ctx)

	token, err := s.httpCookieService.GetSessionToken(r)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeSessionNotFound, "no session token found")
	}

	if token == "" {
		return nil, errors.New(errors.ErrCodeSessionNotFound, "empty session token")
	}

	sessionID, err := s.tokenService.DecryptToken(ctx, token)
	if err != nil {
		s.logger.Error(s.module, requestID, "[getExistingSession]: Failed to decrypt session token: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeTokenDecryption, "failed to decrypt session token")
	}

	existingSession, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		if vaErr, ok := err.(*errors.VigiloAuthError); ok && vaErr.ErrorCode == errors.ErrCodeSessionNotFound {
			s.logger.Debug(s.module, requestID, "[getExistingSession]: Session not found: %v", err)
			return nil, errors.Wrap(err, errors.ErrCodeSessionNotFound, "session not found in storage")
		} else {
			return nil, err
		}
	}

	if time.Now().After(existingSession.ExpirationTime) {
		s.logger.Debug(s.module, requestID, "[getExistingSession]: Session expired")
		return nil, errors.New(errors.ErrCodeSessionExpired, "session has expired")
	}

	s.logger.Debug(s.module, requestID, "[getExistingSession]: Found valid session")
	return existingSession, nil
}
