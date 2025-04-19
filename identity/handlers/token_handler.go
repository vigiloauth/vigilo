package handlers

import (
	"context"
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

	logger *config.Logger
	module string
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
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := common.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[IntrospectToken]: Processing request")

	if err := h.authService.AuthenticateClientRequest(ctx, r, client.TokenIntrospect); err != nil {
		web.WriteError(w, errors.NewClientAuthenticationError(err))
		return
	}

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.NewFormParsingError(err))
		return
	}

	tokenRequest := r.FormValue(common.Token)
	response := h.authService.IntrospectToken(ctx, tokenRequest)

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := common.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[RevokeToken]: Processing request")

	if err := h.authService.AuthenticateClientRequest(ctx, r, client.TokenRevoke); err != nil {
		web.WriteError(w, errors.NewClientAuthenticationError(err))
		return
	}

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.NewFormParsingError(err))
		return
	}

	tokenRequest := r.FormValue(common.Token)
	h.authService.RevokeToken(ctx, tokenRequest)
	web.WriteJSON(w, http.StatusOK, nil)
}

func (h *TokenHandler) IssueTokens(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := common.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[IssueTokens]: Processing request")

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.NewFormParsingError(err))
		return
	}

	clientID, clientSecret, err := h.extractClientCredentials(r)
	if err != nil {
		h.logger.Error(h.module, requestID, "[IssueTokens]: Invalid client credentials: %v", err)
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
		h.handleClientCredentialsRequest(ctx, w, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case client.PasswordGrant:
		h.handlePasswordGrantRequest(ctx, w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case client.AuthorizationCode, client.PKCE:
		h.handleAuthorizationCodeTokenExchange(ctx, w, r, requestID, clientID, clientSecret)
		return
	case client.RefreshToken:
		h.handleRefreshTokenRequest(ctx, w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
	default:
		h.logger.Warn(h.module, requestID, "[IssueTokens]: Unsupported grant type")
		err := errors.New(errors.ErrCodeUnsupportedGrantType, fmt.Sprintf("the provided grant type [%s] is not supported", requestedGrantType))
		web.WriteError(w, err)
		return
	}
}

func (h *TokenHandler) handleClientCredentialsRequest(ctx context.Context, w http.ResponseWriter, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	response, err := h.authService.IssueClientCredentialsToken(ctx, clientID, clientSecret, requestedGrantType, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue token for client credentials grant: %v", err)
		web.WriteError(w, errors.Wrap(err, "", "invalid client credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handlePasswordGrantRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
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

	tokenResponse, err := h.authService.IssueResourceOwnerToken(ctx, clientID, clientSecret, requestedGrantType, requestedScopes, loginAttempt)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue tokens for password grant: %v", err)
		web.WriteError(w, errors.Wrap(err, "", "invalid credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, tokenResponse)
}

func (h *TokenHandler) handleAuthorizationCodeTokenExchange(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret string) {
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
		h.logger.Error(h.module, requestID, "Failed to retrieve session data: %v", err)
		web.WriteError(w, errors.NewInvalidSessionError())
		return
	}

	if sessionData.State != tokenRequest.State {
		err := errors.New(errors.ErrCodeInvalidRequest, "state mismatch between session and request")
		h.logger.Error(h.module, requestID, "State mismatch between session and request")
		web.WriteError(w, err)
		return
	}

	authzCodeData, err := h.authorizationService.AuthorizeTokenExchange(ctx, tokenRequest)
	if err != nil {
		h.logger.Error(h.module, requestID, "Authorization failed for token exchange: %v", err)
		wrappedErr := errors.Wrap(err, "", "authorization failed for token exchange")
		web.WriteError(w, wrappedErr)
		return
	}

	response, err := h.authorizationService.GenerateTokens(ctx, authzCodeData)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to generate access and refresh tokens: %v", err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access & refresh tokens")
		web.WriteError(w, wrappedErr)
		return
	}

	if err := h.sessionService.ClearStateFromSession(ctx, sessionData); err != nil {
		h.logger.Error(h.module, requestID, "Failed to clear state from the current session: %v", err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to clear state from session")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, requestID, "Successfully processed request=[TokenExchange]")
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshTokenRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID, clientID, clientSecret, requestedGrantType, requestedScopes string) {
	refreshToken := r.FormValue(common.RefreshToken)
	if refreshToken == "" || requestedScopes == "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "one or more required parameters are missing"))
		return
	}

	response, err := h.authService.RefreshAccessToken(ctx, clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue new access token: %v", err)
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
