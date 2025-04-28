package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	oidc "github.com/vigiloauth/vigilo/internal/domain/oidc"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/internal/web"
)

type OIDCHandler struct {
	oidcService oidc.OIDCService
	logger      *config.Logger
	module      string
}

func NewOIDCHandler(oidcService oidc.OIDCService) *OIDCHandler {
	return &OIDCHandler{
		oidcService: oidcService,
		logger:      config.GetServerConfig().Logger(),
		module:      "OIDC Handler",
	}
}

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

func (h *OIDCHandler) GetJWKS(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[GetJWKS]: Processing request")
	jwks := h.oidcService.GetJwks(ctx)

	web.WriteJSON(w, http.StatusOK, jwks)
}
