package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
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

	query := r.URL.Query()
	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Processing request")

	if errorURL := web.ValidateClientAuthorizationParameters(query); errorURL != "" {
		h.logger.Error(h.module, requestID, "[AuthorizeClient]: Invalid parameters in the request: %s", utils.SanitizeURL(errorURL))
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}

	req := client.NewClientAuthorizationRequest(query, h.sessionService.GetUserIDFromSession(r))
	if req.UserID == "" {
		loginURL := h.buildLoginURL(req.ClientID, req.RedirectURI, req.Scope, req.State, requestID)
		h.logger.Warn(h.module, requestID, "[AuthorizeClient]: User is not authenticated. Redirecting them to the login page")
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	isUserConsentApproved := query.Get(constants.ConsentApprovedURLValue) == "true"
	redirectURL, err := h.authorizationService.AuthorizeClient(ctx, req, isUserConsentApproved)
	if err != nil {
		if vaErr, ok := err.(*errors.VigiloAuthError); ok && vaErr.ErrorCode == errors.ErrCodeConsentRequired {
			consentURL := vaErr.ConsentURL
			h.logger.Info(h.module, requestID, "[AuthorizeClient]: Consent required. Redirecting to consent URL: %s", utils.SanitizeURL(consentURL))
			http.Redirect(w, r, consentURL, http.StatusFound)
			return
		}

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

	h.logger.Debug(h.module, requestID, "LoginURL=[%s] successfully generated", utils.SanitizeURL(loginURL))
	return loginURL
}
