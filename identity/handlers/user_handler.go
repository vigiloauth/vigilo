package handlers

import (
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	password "github.com/vigiloauth/vigilo/internal/domain/passwordreset"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// UserHandler handles HTTP requests related to user operations.
type UserHandler struct {
	userService          users.UserService
	passwordResetService password.PasswordResetService
	sessionService       session.SessionService
	jwtConfig            *config.TokenConfig

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
// *UserHandler: A new UserHandler instance.
func NewUserHandler(
	userService users.UserService,
	passwordResetService password.PasswordResetService,
	sessionService session.SessionService,
) *UserHandler {
	return &UserHandler{
		userService:          userService,
		passwordResetService: passwordResetService,
		sessionService:       sessionService,
		jwtConfig:            config.GetServerConfig().TokenConfig(),
		logger:               config.GetServerConfig().Logger(),
		module:               "User Handler",
	}
}

// Register is the HTTP handler for user registration.
// It processes incoming HTTP requests for user registration, validates the input,
// registers the user, and sends an appropriate response including a JWT token.
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[Register]", requestID)

	request, err := web.DecodeJSONRequest[users.UserRegistrationRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	user := users.NewUser(request.Username, request.Email, request.Password)
	response, err := h.userService.CreateUser(user)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to create user")
		web.WriteError(w, wrappedErr)
		return
	}

	if err := h.sessionService.CreateSession(w, r, user.ID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, err)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[Register]", requestID)
	web.WriteJSON(w, http.StatusCreated, response)
}

// Login is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful or a generic error
// message for failed attempts.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[Login]", requestID)

	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	response, err := h.userService.AuthenticateUserWithRequest(
		request, r.RemoteAddr,
		r.Header.Get(common.XForwardedHeader),
		r.UserAgent(),
	)

	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate user")
		web.WriteError(w, wrappedErr)
		return
	}

	if err := h.sessionService.CreateSession(w, r, response.UserID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, errors.NewSessionCreationError(err))
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[Login]", requestID)
	web.WriteJSON(w, http.StatusOK, response)
}

// Logout is the HTTP handler for user logout.
// It processes incoming HTTP requests for user logout, validates the JWT token,
// adds the token to the blacklist to prevent further use, and sends an appropriate response.
// If the Authorization header is missing or the token is invalid, it returns an error.
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[Logout]", requestID)

	if err := h.sessionService.InvalidateSession(w, r); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to invalidate session")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[Logout]", requestID)
	w.WriteHeader(http.StatusOK)
}

// ResetPassword handles the password reset request.
// It decodes the request body into a UserPasswordResetRequest, validates the request,
// and then calls the passwordResetService to reset the user's password.
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[ResetPassword]", requestID)

	request, err := web.DecodeJSONRequest[users.UserPasswordResetRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	response, err := h.passwordResetService.ResetPassword(
		request.Email,
		request.NewPassword,
		request.ResetToken,
	)

	if err != nil {
		web.WriteError(w, err)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[ResetPassword]", requestID)
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *UserHandler) VerifyAccount(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[ResetPassword]", requestID)

	query := r.URL.Query()
	verificationToken := query.Get(common.Token)
	if err := h.userService.ValidateVerificationCode(verificationToken); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate user account")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, "")
}
