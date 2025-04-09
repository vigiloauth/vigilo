package handlers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// AuthorizationHandler handles HTTP requests related to authorization.
type AuthorizationHandler struct {
	authorizationService authz.AuthorizationService
	sessionService       session.SessionService

	logger *config.Logger
	module string
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
		logger:               config.GetServerConfig().Logger(),
		module:               "Authorization Handler",
	}
}

// TODO:
// - Add logs
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
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[AuthorizeClient]", requestID)

	query := r.URL.Query()
	isUserConsentApproved := query.Get(common.Approved) == "true"
	req := client.NewClientAuthorizationRequest(
		query.Get(common.ClientID),
		query.Get(common.RedirectURI),
		query.Get(common.Scope),
		query.Get(common.State),
		query.Get(common.ResponseType),
		query.Get(common.CodeChallenge),
		query.Get(common.CodeChallengeMethod),
		h.sessionService.GetUserIDFromSession(r),
	)

	if req.UserID == "" {
		loginURL := h.buildLoginURL(req.ClientID, req.RedirectURI, req.Scope, req.State, requestID)
		h.logger.Warn(h.module, "RequestID=[%s]: User is not authenticated. Returning a 'login required error'", requestID)
		web.WriteError(w, errors.NewLoginRequiredError(loginURL))
		return
	}

	redirectURL, err := h.authorizationService.AuthorizeClient(req, isUserConsentApproved)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authorize client")
		h.logger.Error(h.module, "RequestID=[%s]: Failed to authorize client: %v", requestID, err)
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[AuthorizeClient]", requestID)
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
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[TokenExchange]", requestID)

	err := r.ParseForm()
	if err != nil {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "unable to parse form"))
		return
	}

	tokenRequest := &token.TokenRequest{
		GrantType:         r.FormValue(common.GrantType),
		AuthorizationCode: r.FormValue(common.AuthzCode),
		RedirectURI:       r.FormValue(common.RedirectURI),
		ClientID:          r.FormValue(common.ClientID),
		ClientSecret:      r.FormValue(common.ClientSecret),
		State:             r.FormValue(common.State),
		CodeVerifier:      r.FormValue(common.CodeVerifier),
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

func (h *AuthorizationHandler) buildLoginURL(clientID, redirectURI, scope, state, requestID string) string {
	baseURL := config.GetServerConfig().BaseURL()
	loginURL := fmt.Sprintf("%s%s?client_id=%s&redirect_uri=%s&scope=%s",
		baseURL,
		web.OAuthEndpoints.Login,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
	)

	if state != "" {
		h.logger.Debug(h.module, "RequestID=[%s]: Adding state to login URL", requestID)
		loginURL = fmt.Sprintf("%s&state=%s", loginURL, url.QueryEscape(state))
	}

	h.logger.Debug(h.module, "RequestID=[%s]: LoginURL=[%s] successfully generated", requestID, common.SanitizeURL(loginURL))
	return loginURL
}
