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
	createdUser, err := h.userRegistration.Register(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	h.respondWithToken(w, http.StatusCreated, createdUser)
}

// Login is the HTTP handler for user login.
// It processes incoming HTTP requests for user login, validates the input,
// logs in the user, and returns a JWT token if successful.
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
	_, err := h.userLogin.Login(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	h.respondWithToken(w, http.StatusOK, user)
}

func (h *UserHandler) respondWithToken(w http.ResponseWriter, statusCode int, user *users.User) {
	token, err := security.GenerateJWT(user.Email, *h.jwtConfig)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response := users.NewUserLoginResponse(user.Username, user.Email, token)
	utils.WriteJSON(w, statusCode, response)
}
