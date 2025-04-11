package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

type TokenHandler struct {
	authService          auth.AuthenticationService
	sessionService       session.SessionService
	authorizationService authz.AuthorizationService
	logger               *config.Logger
	module               string
}

func NewTokenHandler(
	authService auth.AuthenticationService,
	sessionService session.SessionService,
	authorizationService authz.AuthorizationService,
) *TokenHandler {
	return &TokenHandler{
		authService:          authService,
		sessionService:       sessionService,
		authorizationService: authorizationService,
		logger:               config.GetServerConfig().Logger(),
		module:               "Token Handler",
	}
}

func (h *TokenHandler) IntrospectToken(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[IntrospectToken]", requestID)

	if err := h.authService.AuthenticateClientRequest(r); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate request")
		web.WriteError(w, wrappedErr)
		return
	}

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "unable to parse form"))
		return
	}

	tokenRequest := r.FormValue(common.Token)
	response := h.authService.IntrospectToken(tokenRequest)

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) IssueTokens(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[IssueToken]", requestID)

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "unable to parse form"))
		return
	}

	clientID, clientSecret, err := h.extractClientCredentials(r)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Invalid client credentials: %v", requestID, err)
		web.WriteError(w, err)
		return
	}

	requestedGrantType := r.FormValue(common.GrantType)
	requestedScopes := r.FormValue(common.Scope)

	if requestedGrantType == "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "one or more required parameters are missing"))
		return
	}

	switch requestedGrantType {
	case client.ClientCredentials:
		h.handleClientCredentialsRequest(w, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case client.PasswordGrant:
		h.handlePasswordGrantRequest(w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case client.AuthorizationCode, client.PKCE:
		h.handleAuthorizationCodeTokenExchange(w, r, requestID, clientID, clientSecret)
		return
	case client.RefreshToken:
		h.handleRefreshTokenRequest(w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
	default:
		h.logger.Warn(h.module, "RequestID=[%s]: Unsupported grant type", requestID)
		err := errors.New(errors.ErrCodeUnsupportedGrantType, fmt.Sprintf("the provided grant type [%s] is not supported", requestedGrantType))
		web.WriteError(w, err)
		return
	}
}

func (h *TokenHandler) handleClientCredentialsRequest(w http.ResponseWriter, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	response, err := h.authService.IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to issue token for client credentials grant: %v", requestID, err)
		web.WriteError(w, errors.Wrap(err, "", "invalid client credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handlePasswordGrantRequest(w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
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

func (h *TokenHandler) handleAuthorizationCodeTokenExchange(w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret string) {
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[TokenExchange]", requestID)

	tokenRequest := &token.TokenRequest{
		GrantType:         r.FormValue(common.GrantType),
		AuthorizationCode: r.FormValue(common.AuthzCode),
		RedirectURI:       r.FormValue(common.RedirectURI),
		ClientID:          clientID,
		State:             r.FormValue(common.State),
	}

	codeVerifier := r.FormValue(common.CodeVerifier)
	if codeVerifier != "" {
		tokenRequest.CodeVerifier = codeVerifier
	}

	if clientSecret != "" {
		tokenRequest.ClientSecret = clientSecret
	}

	sessionData, err := h.sessionService.GetSessionData(r)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to retrieve session data: %v", requestID, err)
		web.WriteError(w, errors.NewInvalidSessionError())
		return
	}

	if sessionData.State != tokenRequest.State {
		err := errors.New(errors.ErrCodeInvalidRequest, "state mismatch between session and request")
		h.logger.Error(h.module, "RequestID=[%s]: State mismatch between session and request", requestID)
		web.WriteError(w, err)
		return
	}

	authzCodeData, err := h.authorizationService.AuthorizeTokenExchange(tokenRequest)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Authorization failed for token exchange: %v", requestID, err)
		wrappedErr := errors.Wrap(err, "", "authorization failed for token exchange")
		web.WriteError(w, wrappedErr)
		return
	}

	response, err := h.authorizationService.GenerateTokens(authzCodeData)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to generate access and refresh tokens: %v", requestID, err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access & refresh tokens")
		web.WriteError(w, wrappedErr)
		return
	}

	if err := h.sessionService.ClearStateFromSession(sessionData); err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to clear state from the current session: %v", requestID, err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to clear state from session")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[TokenExchange]", requestID)
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshTokenRequest(w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	refreshToken := r.FormValue(common.RefreshToken)
	if refreshToken == "" || requestedScopes == "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "one or more required parameters are missing"))
		return
	}

	response, err := h.authService.RefreshAccessToken(clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to issue new access token: %v", requestID, err)
		web.WriteError(w, errors.Wrap(err, "", "failed to issue new access and refresh tokens"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) extractClientCredentials(r *http.Request) (string, string, error) {
	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		clientID = r.FormValue(common.ClientID)
		clientSecret = r.FormValue(common.ClientSecret)
		if clientID == "" {
			return "", "", errors.New(errors.ErrCodeInvalidClient, "missing client identification")
		}
	}

	return clientID, clientSecret, nil
}
