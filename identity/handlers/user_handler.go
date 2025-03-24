package handlers

import (
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
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
	}
}

// Register is the HTTP handler for user registration.
// It processes incoming HTTP requests for user registration, validates the input,
// registers the user, and sends an appropriate response including a JWT token.
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	request, err := web.DecodeJSONRequest[users.UserRegistrationRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request body")
		web.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, err)
		return
	}

	user := users.NewUser(request.Username, request.Email, request.Password)
	response, err := h.userService.CreateUser(user)
	if err != nil {
		web.WriteError(w, err)
		return
	}

	if err := h.sessionService.CreateSession(w, r, user.ID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, err)
		return
	}

	web.WriteJSON(w, http.StatusCreated, response)
}

// Login is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful or a generic error
// message for failed attempts.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request body")
		web.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, err)
		return
	}

	user := &users.User{
		ID:       request.ID,
		Email:    request.Email,
		Password: request.Password,
	}

	loginAttempt := &users.UserLoginAttempt{
		IPAddress:       r.RemoteAddr,
		RequestMetadata: r.Header.Get("X-Forwarded-For"),
		UserAgent:       r.UserAgent(),
	}

	response, err := h.userService.AuthenticateUser(user, loginAttempt)
	if err != nil {
		web.WriteError(w, err)
		return
	}

	if err := h.sessionService.CreateSession(w, r, response.UserID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, err)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// Logout is the HTTP handler for user logout.
// It processes incoming HTTP requests for user logout, validates the JWT token,
// adds the token to the blacklist to prevent further use, and sends an appropriate response.
// If the Authorization header is missing or the token is invalid, it returns an error.
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessionService.InvalidateSession(w, r); err != nil {
		web.WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RequestPasswordResetEmail is HTTP handler for requesting a password reset email.
// It process the incoming request and sends a password reset email to the user if they
// exist with the provided email.
func (h *UserHandler) RequestPasswordResetEmail(w http.ResponseWriter, r *http.Request) {
	request, err := web.DecodeJSONRequest[users.UserPasswordResetRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request body")
		web.WriteError(w, err)
		return
	}

	if request.Email == "" {
		err := errors.New(errors.ErrCodeInvalidFormat, "email is either malformed or missing")
		web.WriteError(w, err)
		return
	}

	response, err := h.passwordResetService.SendPasswordResetEmail(request.Email)
	if err != nil {
		web.WriteError(w, err)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// ResetPassword handles the password reset request.
// It decodes the request body into a UserPasswordResetRequest, validates the request,
// and then calls the passwordResetService to reset the user's password.
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	request, err := web.DecodeJSONRequest[users.UserPasswordResetRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request body")
		web.WriteError(w, err)
		return
	}
	if err := request.Validate(); err != nil {
		web.WriteError(w, err)
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

	web.WriteJSON(w, http.StatusOK, response)
}
