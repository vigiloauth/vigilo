package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	auth "github.com/vigiloauth/vigilo/internal/auth/authentication"
	loginAttempt "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	passwordReset "github.com/vigiloauth/vigilo/internal/auth/passwordreset"
	registration "github.com/vigiloauth/vigilo/internal/auth/registration"
	session "github.com/vigiloauth/vigilo/internal/auth/session"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// UserHandler handles HTTP requests related to user operations.
// It encapsulates user registration functionality and manages the
// communication between HTTP layer and business logic.
type UserHandler struct {
	registrationService  *registration.RegistrationService
	authService          *auth.AuthenticationService
	passwordResetService *passwordReset.PasswordResetService
	sessionService       *session.SessionService
	jwtConfig            *config.JWTConfig
}

// NewUserHandler creates a new instance of UserHandler.
func NewUserHandler(
	registrationService *registration.RegistrationService,
	authService *auth.AuthenticationService,
	passwordResetService *passwordReset.PasswordResetService,
	sessionService *session.SessionService,
) *UserHandler {
	return &UserHandler{
		registrationService:  registrationService,
		authService:          authService,
		passwordResetService: passwordResetService,
		sessionService:       sessionService,
		jwtConfig:            config.GetServerConfig().JWTConfig(),
	}
}

// Register is the HTTP handler for user registration.
// It processes incoming HTTP requests for user registration, validates the input,
// registers the user, and sends an appropriate response including a JWT token.
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var request users.UserRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		utils.WriteError(w, err)
		return
	}

	user := users.NewUser(request.Username, request.Email, request.Password)
	response, err := h.registrationService.RegisterUser(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := h.sessionService.CreateSession(w, user.Email, h.jwtConfig.ExpirationTime()); err != nil {
		utils.WriteError(w, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, response)
}

// Login is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful or a generic error
// message for failed attempts.
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var request users.UserLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		utils.WriteError(w, err)
		return
	}

	user := users.NewUser("", request.Email, request.Password)
	loginAttempt := loginAttempt.NewLoginAttempt(
		r.RemoteAddr,
		r.Header.Get("X-Forwarded-For"),
		"", r.UserAgent(),
	)

	response, err := h.authService.AuthenticateUser(user, loginAttempt)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := h.sessionService.CreateSession(w, user.Email, h.jwtConfig.ExpirationTime()); err != nil {
		utils.WriteError(w, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

// Logout is the HTTP handler for user logout.
// It processes incoming HTTP requests for user logout, validates the JWT token,
// adds the token to the blacklist to prevent further use, and sends an appropriate response.
// If the Authorization header is missing or the token is invalid, it returns an error.
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.sessionService.InvalidateSession(w, r); err != nil {
		utils.WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var request users.UserPasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, err)
		return
	}

	response, err := h.passwordResetService.SendPasswordResetEmail(request.Email)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	utils.WriteJSON(w, http.StatusOK, response)
}
