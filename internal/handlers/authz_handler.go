package handlers

import (
	"net/http"
	"net/url"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// AuthorizationHandler handles HTTP requests related to authorization.
type AuthorizationHandler struct {
	clientAuthorization client.ClientAuthorization

	logger *config.Logger
	module string
}

// NewAuthorizationHandler creates a new AuthorizationHandler instance.
// It initializes the handler with the provided authorization and session services.
func NewAuthorizationHandler(clientAuthorization client.ClientAuthorization) *AuthorizationHandler {
	return &AuthorizationHandler{
		clientAuthorization: clientAuthorization,
		logger:              config.GetServerConfig().Logger(),
		module:              "Authorization Handler",
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
	h.logger.Info(h.module, requestID, "[AuthorizeClient]: Processing request")

	var query url.Values
	if r.Method == http.MethodGet {
		query = r.URL.Query()
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			h.logger.Error(h.module, requestID, "[AuthorizeClient]: Failed to parse form: %v", err)
			web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "invalid form data"))
			return
		}
		query = r.Form
	}

	req := client.NewClientAuthorizationRequest(query)
	req.HTTPWriter = w
	req.HTTPRequest = r

	redirectURL, err := h.clientAuthorization.Authorize(ctx, req)
	if err != nil {
		if errors.ErrorCode(err) == errors.ErrCodeInvalidRedirectURI {
			web.RenderErrorPage(w, r, errors.ErrorCode(err), req.RedirectURI)
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
