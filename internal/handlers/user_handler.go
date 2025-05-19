package handlers

import (
	"context"

	"net/http"
	"net/url"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// UserHandler handles HTTP requests related to user operations.
type UserHandler struct {
	userService    users.UserService
	sessionService session.SessionService
	tokenConfig    *config.TokenConfig

	logger *config.Logger
	module string
}

// NewUserHandler creates a new instance of UserHandler.
//
// Parameters:
//
//	userService UserService: The user service.
//	passwordResetService PasswordResetService: The password reset service.
//	sessionService Session: The session service.
//
// Returns:
//
//	*UserHandler: A new UserHandler instance.
func NewUserHandler(userService users.UserService, sessionService session.SessionService) *UserHandler {
	return &UserHandler{
		userService:    userService,
		sessionService: sessionService,
		tokenConfig:    config.GetServerConfig().TokenConfig(),
		logger:         config.GetServerConfig().Logger(),
		module:         "User Handler",
	}
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[Register]: Processing request")

	request, err := web.DecodeJSONRequest[users.UserRegistrationRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	user := users.NewUserFromRegistrationRequest(request)
	response, err := h.userService.CreateUser(ctx, user)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to create user")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusCreated, response)
}

// Login is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful or a generic error
// message for failed attempts.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[Login]: Processing request")

	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	response, err := h.userService.AuthenticateUserWithRequest(ctx, request)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate user")
		web.WriteError(w, wrappedErr)
		return
	}
	sessionData := &session.SessionData{
		UserID:             response.UserID,
		IPAddress:          r.RemoteAddr,
		UserAgent:          r.UserAgent(),
		AuthenticationTime: time.Now(),
	}

	if err := h.sessionService.CreateSession(w, r, sessionData); err != nil {
		web.WriteError(w, errors.NewSessionCreationError(err))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// OAuthLogin handles login specifically for the OAuth authorization code flow
// It expects the same login credentials as the regular Login endpoint,
// but processes the OAuth context parameters and redirects accordingly
func (h *UserHandler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[OAuthLogin]: Processing request")

	query := r.URL.Query()
	clientID := query.Get(constants.ClientIDReqField)
	redirectURI := query.Get(constants.RedirectURIReqField)

	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	response, err := h.userService.AuthenticateUser(ctx, request, clientID, redirectURI)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate user")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Debug(h.module, requestID, "[OAuthLogin]: UserID: %s", response.UserID)

	sessionData := &session.SessionData{
		UserID:             response.UserID,
		IPAddress:          r.RemoteAddr,
		UserAgent:          r.UserAgent(),
		AuthenticationTime: time.Now(),
	}

	if err := h.sessionService.CreateSession(w, r, sessionData); err != nil {
		web.WriteError(w, errors.NewSessionCreationError(err))
		return
	}

	response.OAuthRedirectURL = h.buildOAuthRedirectURL(query, clientID, redirectURI)
	web.WriteJSON(w, http.StatusOK, response)
}

// Logout is the HTTP handler for user logout.
// It processes incoming HTTP requests for user logout, validates the JWT token,
// adds the token to the blacklist to prevent further use, and sends an appropriate response.
// If the Authorization header is missing or the token is invalid, it returns an error.
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[Logout]: Processing request")

	if err := h.sessionService.InvalidateSession(w, r); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to invalidate session")
		web.WriteError(w, wrappedErr)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ResetPassword handles the password reset request.
// It decodes the request body into a UserPasswordResetRequest, validates the request,
// and then calls the passwordResetService to reset the user's password.
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[ResetPassword]: Processing request")

	request, err := web.DecodeJSONRequest[users.UserPasswordResetRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	response, err := h.userService.ResetPassword(
		ctx,
		request.Email,
		request.NewPassword,
		request.ResetToken,
	)

	if err != nil {
		web.WriteError(w, err)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *UserHandler) VerifyAccount(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[VerifyAccount]: Processing request")

	query := r.URL.Query()
	verificationToken := query.Get(constants.TokenReqField)
	if err := h.userService.ValidateVerificationCode(ctx, verificationToken); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate user account")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, "")
}

func (h *UserHandler) buildOAuthRedirectURL(query url.Values, clientID, redirectURI string) string {
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, clientID)
	queryParams.Add(constants.RedirectURIReqField, redirectURI)

	if state := query.Get(constants.StateReqField); state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if scope := query.Get(constants.ScopeReqField); scope != "" {
		queryParams.Add(constants.ScopeReqField, scope)
	}
	if responseType := query.Get(constants.ResponseTypeReqField); responseType != "" {
		queryParams.Add(constants.ResponseTypeReqField, responseType)
	}
	if nonce := query.Get(constants.NonceReqField); nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}
	if approved := query.Get(constants.ConsentApprovedURLValue); approved != "" {
		queryParams.Add(constants.ConsentApprovedURLValue, approved)
	}

	return "/identity" + web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
}
