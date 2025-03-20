package handlers

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	client "github.com/vigiloauth/vigilo/internal/client/service"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// AuthHandler handles HTTP requests related to authentication.
type AuthHandler struct {
	tokenService  token.TokenService
	clientService client.ClientService
}

// NewAuthHandler creates a new instance of AuthHandler.
//
// Parameters:
//
//	tokenService token.TokenService: The token service.
//	clientService client.ClientService: The client service.
//
// Returns:
//
//	*AuthHandler: A new NewAuthHandler instance.
func NewAuthHandler(tokenService token.TokenService, clientService client.ClientService) *AuthHandler {
	return &AuthHandler{
		tokenService:  tokenService,
		clientService: clientService,
	}
}

// Need docs
// Need tests

// GenerateToken is the handler responsible for generating new tokens.
func (h *AuthHandler) GenerateToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := extractBasicAuth(r)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	if _, err := h.clientService.AuthenticateAndAuthorizeClient(clientID, clientSecret); err != nil {
		utils.WriteError(w, errors.Wrap(err, "", "invalid client credentials"))
		return
	}

	tokenExpirationTime := 30 * time.Minute
	accessToken, err := h.tokenService.GenerateToken(clientID, tokenExpirationTime)
	if err != nil {
		utils.WriteError(w, errors.NewInternalServerError())
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	utils.WriteJSON(w, http.StatusOK, &token.TokenResponse{
		TokenType:   token.BearerToken,
		AccessToken: accessToken,
		ExpiresIn:   int(tokenExpirationTime.Seconds()),
	})
}

// extractBasicAuth extracts and validates Basic Auth credentials from a request
func extractBasicAuth(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", errors.New(errors.ErrCodeInvalidRequest, "invalid authorization header")
	}

	credentials, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials")
	}

	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials format")
	}

	return parts[0], parts[1], nil
}
