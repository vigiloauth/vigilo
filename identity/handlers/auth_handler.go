package handlers

import (
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// AuthenticationHandler handles HTTP requests related to authentication.
type AuthenticationHandler struct {
	tokenService  token.TokenService
	clientService client.ClientService
}

// NewAuthenticationHandler creates a new instance of AuthHandler.
//
// Parameters:
//
//	tokenService token.TokenService: The token service.
//	clientService client.ClientService: The client service.
//
// Returns:
//
//	*AuthHandler: A new AuthHandler instance.
func NewAuthenticationHandler(tokenService token.TokenService, clientService client.ClientService) *AuthenticationHandler {
	return &AuthenticationHandler{
		tokenService:  tokenService,
		clientService: clientService,
	}
}

// IssueClientCredentialsToken is the handler responsible for generating new tokens.
func (h *AuthenticationHandler) IssueClientCredentialsToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "invalid request format"))
		return
	}

	grantType := r.Form.Get(common.GrantType)
	if grantType != common.ClientCredentials {
		web.WriteError(w, errors.New(errors.ErrCodeUnsupportedGrantType, "unsupported grant type"))
		return
	}

	clientID, clientSecret, err := web.ExtractBasicAuth(r)
	if err != nil {
		web.WriteError(w, err)
		return
	}

	if _, err := h.clientService.AuthenticateClientForCredentialsGrant(clientID, clientSecret); err != nil {
		web.WriteError(w, errors.Wrap(err, "", "invalid client credentials"))
		return
	}

	tokenExpirationTime := 30 * time.Minute
	accessToken, err := h.tokenService.GenerateToken(clientID, tokenExpirationTime)
	if err != nil {
		web.WriteError(w, errors.NewInternalServerError())
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	web.WriteJSON(w, http.StatusOK, &token.TokenResponse{
		AccessToken: accessToken,
		TokenType:   token.BearerToken,
		ExpiresIn:   int(tokenExpirationTime.Seconds()),
	})
}
