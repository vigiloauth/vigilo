package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
)

// sessionTokenName is the name of the session token cookie.
const sessionTokenName string = "session_token"

// Session defines the interface for session management.
type Session interface {
	CreateSession(w http.ResponseWriter, email string, sessionExpiration time.Duration) error
	InvalidateSession(w http.ResponseWriter, r *http.Request) error
}

// Ensure SessionService implements the Session interface.
var _ Session = (*SessionService)(nil)

// SessionService handles session management.
type SessionService struct {
	tokenManager   token.TokenService // Token manager for JWT.
	tokenBlacklist token.TokenStore   // Token store for blacklisted tokens.
}

// NewSessionService creates a new instance of SessionService with the required dependencies.
//
// Parameters:
//
//	tokenManager token.TokenManager: The token manager.
//	tokenBlacklist token.TokenStore: The token store for blacklisted tokens.
//
// Returns:
//
//	*SessionService: A new SessionService instance.
func NewSessionService(tokenManager token.TokenService, tokenBlacklist token.TokenStore) *SessionService {
	return &SessionService{
		tokenManager:   tokenManager,
		tokenBlacklist: tokenBlacklist,
	}
}

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
//
// Parameters:
//
//	w http.ResponseWriter: The HTTP response writer.
//	email string: The user's email address.
//	sessionExpiration time.Duration: The session expiration time.
//
// Returns:
//
//	error: An error if token generation or cookie setting fails.
func (s *SessionService) CreateSession(w http.ResponseWriter, email string, sessionExpiration time.Duration) error {
	sessionToken, err := s.tokenManager.GenerateToken(email, sessionExpiration)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeTokenCreation, "failed to generate session token")
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
func (s *SessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	tokenString, err := s.parseToken(r)
	if tokenString == "" || err != nil {
		return errors.Wrap(err, "", "failed to parse token from request headers")
	}

	claims, err := s.generateStandardClaims(tokenString)
	if err != nil {
		return errors.Wrap(err, "", "failed to generate JWT Standard Claims")
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	if expiration.After(time.Now()) {
		s.tokenBlacklist.AddToken(tokenString, claims.Subject, expiration)
	}

	s.setHTTPCookie(&w, "", -time.Hour)
	return nil
}

// parseToken parses the token from the Authorization header.
//
// Parameters:
//
//	r *http.Request: The HTTP request.
//
// Returns:
//
//	string: The token string.
//	error: An error if the token is invalid or missing.
func (s *SessionService) parseToken(r *http.Request) (string, error) {
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
func (s *SessionService) generateStandardClaims(token string) (*jwt.StandardClaims, error) {
	claims, err := s.tokenManager.ParseToken(token)
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
func (s *SessionService) setHTTPCookie(w *http.ResponseWriter, token string, sessionExpiration time.Duration) {
	shouldUseHTTPS := config.GetServerConfig().ForceHTTPS()
	http.SetCookie(*w, &http.Cookie{
		Name:     sessionTokenName,
		Value:    token,
		Expires:  time.Now().Add(sessionExpiration),
		HttpOnly: shouldUseHTTPS,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
