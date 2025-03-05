package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
)

// CreateSession creates a new session token and sets it in an HttpOnly cookie.
func CreateSession(w http.ResponseWriter, email string, jwtConfig *config.JWTConfig) error {
	sessionToken, err := token.GenerateJWT(email, *jwtConfig)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(jwtConfig.ExpirationTime()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}

// InvalidateSession invalidates the session token by adding it to the blacklist.
func InvalidateSession(w http.ResponseWriter, r *http.Request, jwtConfig *config.JWTConfig, tokenBlacklist *token.TokenBlacklist) error {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return errors.NewInvalidCredentialsError()
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := token.ParseJWT(tokenString, *jwtConfig)
	if err != nil {
		return errors.NewInvalidCredentialsError()
	}

	expiration := time.Unix(claims.ExpiresAt, 0)
	tokenBlacklist.AddToken(tokenString, expiration)

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return nil
}
