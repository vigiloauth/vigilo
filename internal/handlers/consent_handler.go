package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/crypto"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/internal/web"
)

// UserHandler handles HTTP requests related to OAuth operations.
type ConsentHandler struct {
	userService    users.UserService
	sessionService session.SessionService
	consentService consent.UserConsentService
	jwtConfig      *config.TokenConfig

	logger *config.Logger
	module string
}

// NewConsentHandler creates a new instance of UserHandler.
//
// Parameters:
//
//	userService UserService: The user service.
//	sessionService Session: The session service.
//	consentService ConsentService: The consent service.
//
// Returns:
// *UserHandler: A new UserHandler instance.
func NewConsentHandler(
	userService users.UserService,
	sessionService session.SessionService,
	consentService consent.UserConsentService,
) *ConsentHandler {
	return &ConsentHandler{
		userService:    userService,
		sessionService: sessionService,
		consentService: consentService,
		jwtConfig:      config.GetServerConfig().TokenConfig(),
		logger:         config.GetServerConfig().Logger(),
		module:         "OAuth Handler",
	}
}

// UserConsent handles user consent decisions for OAuth authorization
func (h *ConsentHandler) UserConsent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[UserConsent]: Processing request")

	query := r.URL.Query()
	clientID := query.Get(constants.ClientIDReqField)
	redirectURI := query.Get(constants.RedirectURIReqField)
	scope := query.Get(constants.ScopeReqField)

	if clientID == "" || redirectURI == "" || scope == "" {
		web.WriteError(w, errors.New(errors.ErrCodeBadRequest, "missing required parameters"))
		return
	}

	// Check if the user is logged in
	userID := h.sessionService.GetUserIDFromSession(r)
	if userID == "" {
		state := crypto.GenerateUUID()
		baseURL := config.GetServerConfig().BaseURL()
		oauthLoginURL := fmt.Sprintf("%s%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			baseURL,
			web.OAuthEndpoints.Login,
			url.QueryEscape(clientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape(scope),
			url.QueryEscape(state))
		web.WriteError(w, errors.NewLoginRequiredError(oauthLoginURL))
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetConsent(w, r, userID, clientID, redirectURI, scope)
	case http.MethodPost:
		h.handlePostConsent(w, r, userID, clientID, redirectURI, scope)
	default:
		web.WriteError(w, errors.NewMethodNotAllowedError(r.Method))
	}
}

// handleGetConsent handles GET requests for user consent
func (h *ConsentHandler) handleGetConsent(w http.ResponseWriter, r *http.Request, userID, clientID, redirectURI, scope string) {
	response, err := h.consentService.GetConsentDetails(userID, clientID, redirectURI, scope, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to retrieve user consent details")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// handlePostConsent handles POST requests for user consent
func (h *ConsentHandler) handlePostConsent(w http.ResponseWriter, r *http.Request, userID, clientID, redirectURI, scope string) {
	consentRequest, err := web.DecodeJSONRequest[consent.UserConsentRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		web.WriteError(w, err)
		return
	}

	response, err := h.consentService.ProcessUserConsent(userID, clientID, redirectURI, scope, consentRequest, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to process user consent")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}
