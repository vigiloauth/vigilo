package handlers

import (
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

type AuthHandler struct {
	authService auth.AuthenticationService
	logger      *config.Logger
	module      string
}

func NewTokenHandler(authService auth.AuthenticationService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      config.GetServerConfig().Logger(),
		module:      "Token Handler",
	}
}

func (h *AuthHandler) IssueTokens(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[IssueToken]", requestID)

	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, errors.ErrCodeInvalidClient, "invalid authorization header")
		h.logger.Error(h.module, "RequestID=[%s]: Invalid authorization header: %v", requestID, err)
		web.WriteError(w, wrappedErr)
		return
	}

	err = r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "unable to parse form"))
		return
	}

	requestedGrantType := r.FormValue(common.GrantType)
	requestedScopes := r.FormValue(common.Scope)

	switch requestedGrantType {
	case client.ClientCredentials:
		h.handleClientCredentialsRequest(w, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case client.PasswordGrant:
		h.handlePasswordGrantRequest(w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	default:
		h.logger.Warn(h.module, "RequestID=[%s]: Unsupported grant type", requestID)
		web.WriteError(w, errors.New(errors.ErrCodeUnsupportedGrantType, "the provided grant type is not supported"))
		return
	}
}

func (h *AuthHandler) handleClientCredentialsRequest(w http.ResponseWriter, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	response, err := h.authService.IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to issue token for client credentials grant: %v", requestID, err)
		web.WriteError(w, errors.Wrap(err, "", "invalid client credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) handlePasswordGrantRequest(w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	if r.URL.Query().Get(common.Password) != "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "password must not be in the URL"))
		return
	}

	username := r.FormValue(common.Username)
	password := r.FormValue(common.Password)

	loginAttempt := &user.UserLoginAttempt{
		Username:        username,
		Password:        password,
		IPAddress:       r.RemoteAddr,
		Timestamp:       time.Now(),
		RequestMetadata: r.Header.Get(common.XForwardedHeader),
		UserAgent:       r.UserAgent(),
	}

	tokenResponse, err := h.authService.IssueResourceOwnerToken(clientID, clientSecret, requestedGrantType, requestedScopes, loginAttempt)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to issue tokens for password grant: %v", requestID, err)
		web.WriteError(w, errors.Wrap(err, "", "invalid credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, tokenResponse)
}
