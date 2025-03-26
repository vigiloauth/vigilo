package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/vigiloauth/vigilo/internal/common"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// AuthorizationHandler handles HTTP requests related to authorization.
type AuthorizationHandler struct {
	authorizationService authz.AuthorizationService
	sessionService       session.SessionService
}

// NewAuthorizationHandler creates a new AuthorizationHandler instance.
// It initializes the handler with the provided authorization and session services.
func NewAuthorizationHandler(
	authorizationService authz.AuthorizationService,
	sessionService session.SessionService,
) *AuthorizationHandler {
	return &AuthorizationHandler{
		authorizationService: authorizationService,
		sessionService:       sessionService,
	}
}

// TODO:
// - Update docs:
//		- JWTTokenConfig
// - End to end test for entire flow

// AuthorizeClient is the HTTP handler responsible for the authorization code flow.
// It retrieves authorization parameters from the request, verifies the user's session,
// and delegates the authorization logic to the AuthorizationService.
//
// Parameters:
//
//   - w: http.ResponseWriter for writing the HTTP response.
//   - r: *http.Request containing the authorization request parameters.
//
// It handles login redirection, authorization code generation, and consent verification.
// If authorization is successful, it redirects the user to the redirect URI with the authorization code.
// If an error occurs, it writes an appropriate error response.
func (h *AuthorizationHandler) AuthorizeClient(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get(common.ClientID)
	redirectURI := query.Get(common.RedirectURI)
	scope := query.Get(common.Scope)
	approved := query.Get(common.Approved) == "true"
	state := query.Get(common.State)

	userID := h.sessionService.GetUserIDFromSession(r)
	if userID == "" {
		loginURL := h.buildLoginURL(clientID, redirectURI, scope, state)
		web.WriteError(w, errors.NewLoginRequiredError(loginURL))
		return
	}

	redirectURL, err := h.authorizationService.AuthorizeClient(userID, clientID, redirectURI, scope, state, approved)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authorize client")
		web.WriteError(w, wrappedErr)
		return
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// TokenExchange handles the token endpoint for OAuth 2.0 authorization code grant.
//
// It decodes the token request, validates it, authorizes the token exchange,
// generates access and refresh tokens, and writes the token response as JSON.
//
// Parameters:
//
//	w http.ResponseWriter: The HTTP response writer.
//	r *http.Request: The HTTP request.
func (h *AuthorizationHandler) TokenExchange(w http.ResponseWriter, r *http.Request) {
	tokenRequest, err := web.DecodeJSONRequest[token.TokenRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	sessionData, err := h.sessionService.GetSessionData(r)
	if err != nil {
		web.WriteError(w, errors.NewInvalidSessionError())
		return
	}

	if sessionData.State != tokenRequest.State {
		err := errors.New(errors.ErrCodeInvalidRequest, "state mismatch between session and request")
		web.WriteError(w, err)
		return
	}

	authzCodeData, err := h.authorizationService.AuthorizeTokenExchange(tokenRequest)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "authorization failed for token exchange")
		web.WriteError(w, wrappedErr)
		return
	}

	response, err := h.authorizationService.GenerateTokens(authzCodeData)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to generate access & refresh tokens")
		web.WriteError(w, wrappedErr)
		return
	}

	sessionData.State = ""
	if err := h.sessionService.UpdateSession(r, sessionData); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to update state")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *AuthorizationHandler) buildLoginURL(clientID, redirectURI, scope, state string) string {
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s",
		web.OAuthEndpoints.Login,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
	)

	if state != "" {
		URL = fmt.Sprintf("%s&state=%s", URL, url.QueryEscape(state))
	}

	return URL
}
