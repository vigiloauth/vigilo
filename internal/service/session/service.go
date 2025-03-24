package service

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// sessionTokenName is the name of the session token cookie.
const sessionTokenName string = "session_token"

// Ensure SessionService implements the Session interface.
var _ session.SessionService = (*SessionServiceImpl)(nil)

// SessionServiceImpl handles session management.
type SessionServiceImpl struct {
	tokenService token.TokenService
	sessionRepo  session.SessionRepository
}

// NewSessionServiceImpl creates a new instance of SessionService with the required dependencies.
//
// Parameters:
//
//	tokenService TokenService: The token service.
//	sessionRepo SessionRepository: The session repository.
//
// Returns:
//
//	*SessionService: A new SessionService instance.
func NewSessionServiceImpl(
	tokenService token.TokenService,
	sessionRepo session.SessionRepository,
) *SessionServiceImpl {
	return &SessionServiceImpl{
		tokenService: tokenService,
		sessionRepo:  sessionRepo,
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
func (s *SessionServiceImpl) CreateSession(w http.ResponseWriter, r *http.Request, userID string, sessionExpiration time.Duration) error {
	sessionToken, err := s.tokenService.GenerateToken(userID, sessionExpiration)
	if err != nil {
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
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "error creating session")
	}

	s.setHTTPCookie(&w, sessionToken, sessionExpiration)
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
func (s *SessionServiceImpl) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	tokenString, err := s.parseTokenFromAuthzHeader(r)
	if tokenString == "" || err != nil {
		return errors.Wrap(err, "", "failed to parse token from request headers")
	}

	claims, err := s.generateStandardClaims(tokenString)
	if err != nil {
		return errors.Wrap(err, "", "failed to generate JWT Standard Claims")
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	if expiration.After(time.Now()) {
		s.tokenService.SaveToken(tokenString, claims.Subject, expiration)
	}

	sessionID := claims.Subject
	if err := s.sessionRepo.DeleteSessionByID(sessionID); err != nil {
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate session")
	}

	s.setHTTPCookie(&w, "", -time.Hour)
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
func (s *SessionServiceImpl) GetUserIDFromSession(r *http.Request) string {
	tokenString, err := s.getSessionIDFromRequest(r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
		log.Printf("ERR: %s", err)
		return ""
	}

	claims, err := s.tokenService.ParseToken(tokenString)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to parse session token")
		log.Printf("ERR: %s", err)
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
//	error: If an erroor occurs during the update.
func (s *SessionServiceImpl) UpdateSession(r *http.Request, sessionData *session.SessionData) error {
	sessionID, err := s.getSessionIDFromRequest(r)
	if err != nil {
		return errors.Wrap(err, "", "failed to retrieve session ID")
	}

	if sessionID != sessionData.ID {
		return errors.New(errors.ErrCodeUnauthorized, "session IDs do no match")
	}

	if err := s.sessionRepo.UpdateSessionByID(sessionID, sessionData); err != nil {
		return errors.Wrap(err, "", "failed to update session")
	}

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
func (s *SessionServiceImpl) GetSessionData(r *http.Request) (*session.SessionData, error) {
	sessionID, err := s.getSessionIDFromRequest(r)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to retrieve session data")
	}

	sessionData, err := s.sessionRepo.GetSessionByID(sessionID)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to retrieve session from store")
	}

	if sessionData == nil {
		return nil, errors.New(errors.ErrCodeSessionNotFound, "session not found")
	}

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
func (s *SessionServiceImpl) parseTokenFromAuthzHeader(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return "", errors.New(errors.ErrCodeInvalidFormat, "malformed authorization header")
	}

	return token, nil
}

func (s *SessionServiceImpl) getSessionIDFromRequest(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionTokenName)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found in header")
	}
	return cookie.Value, nil
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
func (s *SessionServiceImpl) generateStandardClaims(token string) (*jwt.StandardClaims, error) {
	claims, err := s.tokenService.ParseToken(token)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse token")
	}

	return claims, nil
}

// setHTTPCookie sets the session token as an HttpOnly cookie.
//
// Parameters:
//
//	w *http.ResponseWriter: The HTTP response writer.
//	token string: The session token.
//	sessionExpiration time.Duration: The session expiration time.
func (s *SessionServiceImpl) setHTTPCookie(w *http.ResponseWriter, token string, sessionExpiration time.Duration) {
	shouldUseHTTPS := config.GetServerConfig().ForceHTTPS()
	http.SetCookie(*w, &http.Cookie{
		Name:     sessionTokenName,
		Value:    token,
		Expires:  time.Now().Add(sessionExpiration),
		HttpOnly: true,
		Secure:   shouldUseHTTPS,
		SameSite: http.SameSiteStrictMode,
	})
}
