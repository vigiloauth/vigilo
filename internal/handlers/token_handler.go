package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

type TokenHandler struct {
	grantProcessor token.TokenGrantProcessor
	logger         *config.Logger
	module         string
}

func NewTokenHandler(grantProcessor token.TokenGrantProcessor) *TokenHandler {
	return &TokenHandler{
		grantProcessor: grantProcessor,
		logger:         config.GetServerConfig().Logger(),
		module:         "Token Handler",
	}
}

func (h *TokenHandler) IntrospectToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[IntrospectToken]: Processing request")

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.NewFormParsingError(err))
		return
	}

	tokenStr := r.FormValue(constants.TokenReqField)
	response, err := h.grantProcessor.IntrospectToken(ctx, r, tokenStr)

	if err != nil {
		h.logger.Error(h.module, requestID, "[IntrospectToken]: Failed to introspect token: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to introspect token")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[RevokeToken]: Processing request")

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.NewFormParsingError(err))
		return
	}

	tokenStr := r.FormValue(constants.TokenReqField)
	if err := h.grantProcessor.RevokeToken(ctx, r, tokenStr); err != nil {
		h.logger.Error(h.module, requestID, "[RevokeToken]: Failed to revoke token: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to revoke token")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, nil)
}

func (h *TokenHandler) IssueTokens(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
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

	requestedGrantType := r.FormValue(constants.GrantTypeReqField)
	requestedScopes := types.Scope(r.FormValue(constants.ScopeReqField))

	if requestedGrantType == "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "one or more required parameters are missing"))
		return
	}

	switch requestedGrantType {
	case constants.ClientCredentialsGrantType:
		h.handleClientCredentialsRequest(ctx, w, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case constants.PasswordGrantType:
		h.handlePasswordGrantRequest(ctx, w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
		return
	case constants.AuthorizationCodeGrantType:
		h.handleAuthorizationCodeTokenExchange(ctx, w, r, requestID, clientID, clientSecret)
		return
	case constants.RefreshTokenGrantType:
		h.handleRefreshTokenRequest(ctx, w, r, requestID, clientID, clientSecret, requestedGrantType, requestedScopes)
	default:
		h.logger.Warn(h.module, requestID, "[IssueTokens]: Unsupported grant type")
		err := errors.New(errors.ErrCodeUnsupportedGrantType, fmt.Sprintf("the provided grant type [%s] is not supported", requestedGrantType))
		web.WriteError(w, err)
		return
	}
}

func (h *TokenHandler) handleClientCredentialsRequest(
	ctx context.Context,
	w http.ResponseWriter,
	requestID string,
	clientID string,
	clientSecret string,
	requestedGrantType string,
	requestedScopes types.Scope,
) {
	response, err := h.grantProcessor.IssueClientCredentialsToken(ctx, clientID, clientSecret, requestedGrantType, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue token for client credentials grant: %v", err)
		web.WriteError(w, errors.Wrap(err, "", "invalid client credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handlePasswordGrantRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	clientID string,
	clientSecret string,
	requestedGrantType string,
	requestedScopes types.Scope,
) {
	if r.URL.Query().Get(constants.PasswordReqField) != "" {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "password must not be in the URL"))
		return
	}

	username := r.FormValue(constants.UsernameReqField)
	password := r.FormValue(constants.PasswordReqField)

	userAuthRequest := &user.UserLoginRequest{
		Username: username,
		Password: password,
	}

	tokenResponse, err := h.grantProcessor.IssueResourceOwnerToken(ctx, clientID, clientSecret, requestedGrantType, requestedScopes, userAuthRequest)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue tokens for password grant: %v", err)
		web.WriteError(w, errors.Wrap(err, "", "invalid credentials or unauthorized grant type/scopes"))
		return
	}

	web.WriteJSON(w, http.StatusOK, tokenResponse)
}

func (h *TokenHandler) handleAuthorizationCodeTokenExchange(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	clientID string,
	clientSecret string,
) {
	tokenRequest := &token.TokenRequest{
		GrantType:         r.FormValue(constants.GrantTypeReqField),
		AuthorizationCode: r.FormValue(constants.CodeURLValue),
		RedirectURI:       r.FormValue(constants.RedirectURIReqField),
		ClientID:          clientID,
		State:             r.FormValue(constants.StateReqField),
	}

	codeVerifier := r.FormValue(constants.CodeVerifierReqField)
	if codeVerifier != "" {
		tokenRequest.CodeVerifier = codeVerifier
	}

	if clientSecret != "" {
		tokenRequest.ClientSecret = clientSecret
	}

	response, err := h.grantProcessor.ExchangeAuthorizationCode(ctx, tokenRequest)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to generate access and refresh tokens: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to generate access & refresh tokens")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, requestID, "Successfully processed request=[TokenExchange]")
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) handleRefreshTokenRequest(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	clientID string,
	clientSecret string,
	requestedGrantType string,
	requestedScopes types.Scope,
) {
	refreshToken := r.FormValue(constants.RefreshTokenURLValue)
	response, err := h.grantProcessor.RefreshToken(ctx, clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to issue new access token: %v", err)
		web.SetNoStoreHeader(w)
		web.WriteError(w, errors.Wrap(err, "", "failed to issue new access and refresh tokens"))
		return
	}

	web.SetNoStoreHeader(w)
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *TokenHandler) extractClientCredentials(r *http.Request) (string, string, error) {
	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		clientID = r.FormValue(constants.ClientIDReqField)
		clientSecret = r.FormValue(constants.ClientSecretReqField)
		if clientID == "" {
			return "", "", errors.New(errors.ErrCodeInvalidClient, "missing client identification")
		}
	}

	if decodedSecret, err := url.QueryUnescape(clientSecret); err == nil {
		clientSecret = decodedSecret
	}

	return clientID, clientSecret, nil
}
