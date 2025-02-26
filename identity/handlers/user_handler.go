package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// UserHandler handles HTTP requests related to user operations.
// It encapsulates user registration functionality and manages the
// communication between HTTP layer and business logic.
type UserHandler struct {
	userRegistration *users.UserRegistration
	userLogin        *users.UserLogin
}

// NewUserHandler creates a new instance of UserHandler.
func NewUserHandler(userRegistration *users.UserRegistration, userLogin *users.UserLogin) *UserHandler {
	return &UserHandler{
		userRegistration: userRegistration,
		userLogin:        userLogin,
	}
}

// HandleUserRegistration is the HTTP handler for user registration.
// It processes incoming HTTP requests for user registration, validates the input,
// registers the user, and sends an appropriate response.
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

	user := users.NewUser(request.Username, request.Email, request.Password)
	createdUser, err := h.userRegistration.RegisterUser(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response := users.NewUserRegistrationResponse(createdUser.Username, createdUser.Email)
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

	// TODO - replace this with token goneration
	response := users.NewUserLoginResponse()
	utils.WriteJSON(w, http.StatusOK, response)
}
