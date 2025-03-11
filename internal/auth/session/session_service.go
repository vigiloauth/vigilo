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

const sessionTokenName string = "session_token"

type Session interface {
	CreateSession(w http.ResponseWriter, email string, sessionExpiration time.Duration) error
	InvalidateSession(w http.ResponseWriter, r *http.Request) error
}

var _ Session = (*SessionService)(nil)

// SessionService handles session management.
type SessionService struct {
	tokenManager   token.TokenManager
	tokenBlacklist token.TokenStore
}

// NewSessionService creates a new instance of SessionService with the required dependencies.
func NewSessionService(tokenManager token.TokenManager, tokenBlacklist token.TokenStore) *SessionService {
	return &SessionService{
		tokenManager:   tokenManager,
		tokenBlacklist: tokenBlacklist,
	}
}

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
func (s *SessionService) CreateSession(w http.ResponseWriter, email string, sessionExpiration time.Duration) error {
	sessionToken, err := s.tokenManager.GenerateToken(email, sessionExpiration)
	if err != nil {
		return errors.Wrap(err, "Failed to generate token")
	}

	s.setHTTPCookie(&w, sessionToken, sessionExpiration)
	return nil
}

// InvalidateSession invalidates the session token by adding it to the blacklist.
func (s *SessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	tokenString, err := s.parseToken(r)
	if tokenString == "" || err != nil {
		return errors.Wrap(err, "Failed to parse token from request headers")
	}

	claims, err := s.generateStandardClaims(tokenString)
	if err != nil {
		return errors.Wrap(err, "Failed to generate JWT Standard Claims")
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	if expiration.After(time.Now()) {
		s.tokenBlacklist.AddToken(tokenString, claims.Subject, expiration)
	}

	s.setHTTPCookie(&w, "", -time.Hour)
	return nil
}

func (s *SessionService) parseToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.NewInvalidCredentialsError()
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		return "", errors.Wrap(nil, "invalid authorization header")
	}

	return token, nil
}

func (s *SessionService) generateStandardClaims(token string) (*jwt.StandardClaims, error) {
	claims, err := s.tokenManager.ParseToken(token)
	if err != nil {
		return nil, errors.NewInvalidCredentialsError()
	}

	return claims, nil
}

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
