package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
)

const sessionTokenName string = "session_token"

// SessionService handles session management.
type SessionService struct {
	tokenService   *token.TokenService
	tokenBlacklist token.TokenStore
}

// NewSessionService creates a new instance of SessionService with the required dependencies.
func NewSessionService(tokenService *token.TokenService, tokenBlacklist token.TokenStore) *SessionService {
	return &SessionService{
		tokenService:   tokenService,
		tokenBlacklist: tokenBlacklist,
	}
}

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
func (s *SessionService) CreateSession(w http.ResponseWriter, email string, sessionExpiration time.Duration) error {
	sessionToken, err := s.tokenService.GenerateToken(email, sessionExpiration)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionTokenName,
		Value:    sessionToken,
		Expires:  time.Now().Add(sessionExpiration),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

// InvalidateSession invalidates the session token by adding it to the blacklist.
func (s *SessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return errors.NewInvalidCredentialsError()
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := s.tokenService.ParseToken(tokenString)
	if err != nil {
		return errors.NewInvalidCredentialsError()
	}

	expiration := time.Unix(claims.ExpiresAt, 0)

	if expiration.After(time.Now()) {
		s.tokenBlacklist.AddToken(tokenString, claims.Subject, expiration)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionTokenName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}
