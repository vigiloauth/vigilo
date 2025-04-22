package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
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
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := common.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Processing request=[AuthorizeClient]")

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
		h.logger.Warn(h.module, requestID, "[AuthorizeClient]: User is not authenticated. Returning a 'login required error'")
		web.WriteError(w, errors.NewLoginRequiredError(loginURL))
		return
	}

	redirectURL, err := h.authorizationService.AuthorizeClient(ctx, req, isUserConsentApproved)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authorize client")
		h.logger.Error(h.module, requestID, "[AuthorizeClient]: Failed to authorize client: %v", err)
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Successfully processed request")
	http.Redirect(w, r, redirectURL, http.StatusFound)
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
		h.logger.Debug(h.module, requestID, "Adding state to login URL")
		loginURL = fmt.Sprintf("%s&state=%s", loginURL, url.QueryEscape(state))
	}

	h.logger.Debug(h.module, requestID, "LoginURL=[%s] successfully generated", common.SanitizeURL(loginURL))
	return loginURL
}
