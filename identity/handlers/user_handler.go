package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// UserHandler handles HTTP requests related to user operations.
// It encapsulates user registration functionality and manages the
// communication between HTTP layer and business logic.
type UserHandler struct {
	userRegistration *users.UserRegistration
	userLogin        *auth.UserLogin
	jwtConfig        *config.JWTConfig
	TokenBlacklist   *token.TokenBlacklist
}

// NewUserHandler creates a new instance of UserHandler.
func NewUserHandler(userRegistration *users.UserRegistration, userLogin *auth.UserLogin, jwtConfig *config.JWTConfig) *UserHandler {
	return &UserHandler{
		userRegistration: userRegistration,
		userLogin:        userLogin,
		jwtConfig:        jwtConfig,
		TokenBlacklist:   token.GetTokenBlacklist(),
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
	response, err := h.userRegistration.Register(user)
	if err != nil {
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
	loginAttempt := auth.NewLoginAttempt(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), "", r.UserAgent())

	response, err := h.userLogin.Login(user, loginAttempt)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := auth.CreateSession(w, user.Email, h.jwtConfig); err != nil {
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
	if err := auth.InvalidateSession(w, r, h.jwtConfig, h.TokenBlacklist); err != nil {
		utils.WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
