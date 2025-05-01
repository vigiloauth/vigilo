package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	oidc "github.com/vigiloauth/vigilo/v2/internal/domain/oidc"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// OIDCHandler handles OpenID Connect-related HTTP requests.
type OIDCHandler struct {
	oidcService oidc.OIDCService
	logger      *config.Logger
	module      string
}

// NewOIDCHandler creates a new instance of OIDCHandler.
//
// Parameters:
//   - oidcService oidc.OIDCService: The OIDC service to use.
//
// Returns:
//   - *OIDCHandler: A new OIDCHandler instance.
func NewOIDCHandler(oidcService oidc.OIDCService) *OIDCHandler {
	return &OIDCHandler{
		oidcService: oidcService,
		logger:      config.GetServerConfig().Logger(),
		module:      "OIDC Handler",
	}
}

// GetUserInfo handles the UserInfo endpoint of the ODIC specification.
//
// Parameters:
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//
// Behavior:
//   - Retrieves token claims from the request context.
//   - Calls the OIDC service to fetch user information based on token claims.
//   - Returns the user information as a JSON response or an error if something goes wrong.
func (h *OIDCHandler) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[UserInfo]: Processing request")

	claims := utils.GetValueFromContext(ctx, constants.ContextKeyTokenClaims)
	if claims == nil {
		h.logger.Warn(h.module, requestID, "[UserInfo]: Token claims not found in context")
		web.WriteError(w, errors.New(errors.ErrCodeUnauthorized, "invalid or missing access token"))
		return
	}

	tokenClaims, ok := claims.(*token.TokenClaims)
	if !ok {
		h.logger.Error(h.module, requestID, "[UserInfo]: Invalid token claims type in context")
		web.WriteError(w, errors.NewInternalServerError())
		return
	}

	userInfoResponse, err := h.oidcService.GetUserInfo(ctx, tokenClaims, r)
	if err != nil {
		h.logger.Error(h.module, requestID, "[UserInfo]: An error occurred processing the request: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to retrieve the requested user info")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, userInfoResponse)
}

// GetJWKS handles the JWKS (JSON Web Key Set) endpoint of the OIDC specification.
//
// Parameters:
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//
// Behavior:
//   - Calls the OIDC service to retrieve the JWKS.
//   - Returns the JWKS as a JSON response.
func (h *OIDCHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[GetJWKS]: Processing request")
	jwks := h.oidcService.GetJwks(ctx)

	web.WriteJSON(w, http.StatusOK, jwks)
}

// GetOpenIDConfiguration handles the OpenID Provider Configuration endpoint.
//
// Parameters:
//   - w http.ResponseWriter: The HTTP response writer.
//   - r *http.Request: The HTTP request.
//
// Behavior:
//   - Constructs the OpenID Provider Configuration JSON object.
//   - Returns the configuration as a JSON response.
func (h *OIDCHandler) GetOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[GetOpenIDConfiguration]: Processing request")

	URL := config.GetServerConfig().URL()
	discoveryJSON := oidc.NewDiscoveryJSON(URL)

	web.WriteJSON(w, http.StatusOK, discoveryJSON)
}
