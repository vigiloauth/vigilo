package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// UserHandler handles HTTP requests related to user operations.
// It encapsulates user registration functionality and manages the
// communication between HTTP layer and business logic.
type UserHandler struct {
	userRegistration *users.UserRegistration
	userLogin        *users.UserLogin
	jwtConfig        *config.JWTConfig
}

// NewUserHandler creates a new instance of UserHandler.
func NewUserHandler(userRegistration *users.UserRegistration, userLogin *users.UserLogin, jwtConfig *config.JWTConfig) *UserHandler {
	return &UserHandler{
		userRegistration: userRegistration,
		userLogin:        userLogin,
		jwtConfig:        jwtConfig,
	}
}

// HandleUserRegistration is the HTTP handler for user registration.
// It processes incoming HTTP requests for user registration, validates the input,
// registers the user, and sends an appropriate response including a JWT token.
func (h *UserHandler) HandleUserRegistration(w http.ResponseWriter, r *http.Request) {
	var request users.UserRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		utils.WriteError(w, err)
		return
	}

	hashedPassword, err := security.HashPassword(request.Password)
	if err != nil {
		utils.WriteError(w, err)
		return
	}
	user := users.NewUser(request.Username, request.Email, hashedPassword)
	createdUser, err := h.userRegistration.RegisterUser(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response := users.NewUserRegistrationResponse(createdUser.Username, createdUser.Email)
	token, err := security.GenerateJWT(createdUser.Email, *h.jwtConfig)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response.JWTToken = token
	utils.WriteJSON(w, http.StatusCreated, response)
}

// HandleUserLogin is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful.
func (h *UserHandler) HandleUserLogin(w http.ResponseWriter, r *http.Request) {
	var request users.UserLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, err)
		return
	}

	user := users.NewUser("", request.Email, request.Password)
	_, err := h.userLogin.LoginUser(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	token, err := security.GenerateJWT(user.Email, *h.jwtConfig)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response := users.NewUserLoginResponse(user.Email, token)
	utils.WriteJSON(w, http.StatusOK, response)
}
