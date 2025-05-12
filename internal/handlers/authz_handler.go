package handlers

import (
	"net/http"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// AuthorizationHandler handles HTTP requests related to authorization.
type AuthorizationHandler struct {
	authorizationService authz.AuthorizationService

	logger *config.Logger
	module string
}

// NewAuthorizationHandler creates a new AuthorizationHandler instance.
// It initializes the handler with the provided authorization and session services.
func NewAuthorizationHandler(authorizationService authz.AuthorizationService) *AuthorizationHandler {
	return &AuthorizationHandler{
		authorizationService: authorizationService,
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
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	query := r.URL.Query()
	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Processing request")

	if errorURL := web.ValidateClientAuthorizationParameters(query); errorURL != "" {
		h.logger.Error(h.module, requestID, "[AuthorizeClient]: Invalid parameters in the request: %s", utils.SanitizeURL(errorURL))
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}

	req := client.NewClientAuthorizationRequest(query)
	req.HTTPWriter = w
	req.HTTPRequest = r

	redirectURL, err := h.authorizationService.AuthorizeClient(ctx, req)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authorize client")
		h.logger.Error(h.module, requestID, "[AuthorizeClient]: Failed to authorize client: %v", err)
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Successfully processed request")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
