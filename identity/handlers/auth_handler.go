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
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "the request body format is invalid"))
		return
	}

	if !h.isRequestGrantTypeClientCredentials(r) {
		web.WriteError(w, errors.New(errors.ErrCodeUnsupportedGrantType, "the provided grant type is not supported"))
		return
	}

	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "invalid authorization header")
		web.WriteError(w, wrappedErr)
		return
	}

	if _, err := h.clientService.AuthenticateClientForCredentialsGrant(clientID, clientSecret); err != nil {
		web.WriteError(w, errors.Wrap(err, "", "the client credentials are invalid or incorrectly formatted"))
		return
	}

	tokenExpirationTime := 30 * time.Minute
	accessToken, err := h.tokenService.GenerateToken(clientID, tokenExpirationTime)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to generate access token")
		web.WriteError(w, wrappedErr)
		return
	}

	web.SetNoStoreHeader(w)
	web.WriteJSON(w, http.StatusOK, &token.TokenResponse{
		AccessToken: accessToken,
		TokenType:   token.BearerToken,
		ExpiresIn:   int(tokenExpirationTime.Seconds()),
	})
}

func (h *AuthenticationHandler) isRequestGrantTypeClientCredentials(r *http.Request) bool {
	return r.Form.Get(common.GrantType) == common.ClientCredentials
}
