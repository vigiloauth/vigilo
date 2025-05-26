package handlers

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// UserHandler handles HTTP requests related to OAuth operations.
type ConsentHandler struct {
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

	sessionService session.SessionService,
	consentService consent.UserConsentService,
) *ConsentHandler {
	return &ConsentHandler{

		sessionService: sessionService,
		consentService: consentService,
		jwtConfig:      config.GetServerConfig().TokenConfig(),
		logger:         config.GetServerConfig().Logger(),
		module:         "User Consent Handler",
	}
}

// HandleUserConsent handles user consent decisions for OAuth authorization
func (h *ConsentHandler) HandleUserConsent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[UserConsent]: Processing request")

	query := r.URL.Query()
	clientID := query.Get(constants.ClientIDReqField)
	redirectURI := query.Get(constants.RedirectURIReqField)
	scope := types.Scope(query.Get(constants.ScopeReqField))
	responseType := query.Get(constants.ResponseTypeReqField)
	state := query.Get(constants.StateReqField)
	nonce := query.Get(constants.NonceReqField)
	display := query.Get(constants.DisplayReqField)
	acrValues := query.Get(constants.ACRReqField)
	claims := query.Get(constants.ClaimsReqField)

	if clientID == "" || redirectURI == "" || scope == "" {
		web.WriteError(w, errors.New(errors.ErrCodeBadRequest, "missing required parameters"))
		return
	}

	// Check if the user is logged in
	userID, err := h.sessionService.GetUserIDFromSession(r)
	if err != nil {
		h.logger.Error(h.module, requestID, "[UserConsent]: Failed to retrieve user ID from session: %v", err)
		oauthLoginURL := h.buildLoginURL(clientID, redirectURI, scope.String(), responseType, state, nonce, display)
		http.Redirect(w, r, oauthLoginURL, http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetConsent(w, r, userID, clientID, redirectURI, scope, responseType, state, nonce, display)
	case http.MethodPost:
		h.handlePostConsent(w, r, userID, clientID, redirectURI, scope, responseType, state, nonce, display, acrValues, claims)
	default:
		web.WriteError(w, errors.NewMethodNotAllowedError(r.Method))
	}
}

// handleGetConsent handles GET requests for user consent
func (h *ConsentHandler) handleGetConsent(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
	clientID string,
	redirectURI string,
	scope types.Scope,
	responseType string,
	state string,
	nonce string,
	display string,
) {
	response, err := h.consentService.GetConsentDetails(userID, clientID, redirectURI, state, scope, responseType, nonce, display, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to retrieve user consent details")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// handlePostConsent handles POST requests for user consent
func (h *ConsentHandler) handlePostConsent(w http.ResponseWriter,
	r *http.Request,
	userID string,
	clientID string,
	redirectURI string,
	scope types.Scope,
	responseType string,
	state string,
	nonce string,
	display string,
	acrValues string,
	claims string,
) {
	consentRequest, err := web.DecodeJSONRequest[consent.UserConsentRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		web.WriteError(w, err)
		return
	}

	consentRequest.ResponseType = responseType
	consentRequest.State = state
	consentRequest.Nonce = nonce
	consentRequest.Display = display

	response, err := h.consentService.ProcessUserConsent(
		userID,
		clientID,
		redirectURI,
		scope,
		consentRequest,
		r,
	)

	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to process user consent")
		web.WriteError(w, wrappedErr)
		return
	}

	response.RedirectURI = h.buildOAuthRedirectURL(
		clientID,
		redirectURI,
		scope.String(),
		responseType,
		state,
		nonce,
		display,
		acrValues,
		claims,
		response.Approved,
	)
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *ConsentHandler) buildLoginURL(
	clientID string,
	redirectURI string,
	scope string,
	responseType string,
	state string,
	nonce string,
	display string,
) string {
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, clientID)
	queryParams.Add(constants.RedirectURIReqField, redirectURI)
	queryParams.Add(constants.ScopeReqField, scope)
	queryParams.Add(constants.ResponseTypeReqField, responseType)

	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}

	if display != "" && constants.ValidAuthenticationDisplays[display] {
		queryParams.Add(constants.DisplayReqField, display)
	} else {
		queryParams.Add(constants.DisplayReqField, constants.DisplayPage)
	}

	return "/authenticate?" + queryParams.Encode()
}

func (h *ConsentHandler) buildOAuthRedirectURL(
	clientID string,
	redirectURI string,
	scope string,
	responseType string,
	state string,
	nonce string,
	display string,
	acrValues string,
	claims string,
	approved bool,
) string {
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, clientID)
	queryParams.Add(constants.RedirectURIReqField, redirectURI)
	queryParams.Add(constants.ConsentApprovedURLValue, strconv.FormatBool(approved))

	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if scope != "" {
		queryParams.Add(constants.ScopeReqField, scope)
	}
	if responseType != "" {
		queryParams.Add(constants.ResponseTypeReqField, responseType)
	}
	if nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}
	if display != "" {
		queryParams.Add(constants.DisplayReqField, display)
	}
	if acrValues != "" {
		queryParams.Add(constants.ACRReqField, acrValues)
	}
	if claims != "" {
		queryParams.Add(constants.ClaimsReqField, claims)
	}

	return "/identity" + web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
}
