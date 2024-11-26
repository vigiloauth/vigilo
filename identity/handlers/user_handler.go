package handlers

import (
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
	"net/http"
)

// UserHandler handles HTTP requests related to user operations.
// It encapsulates user registration functionality and manages the
// communication between HTTP layer and business logic.
type UserHandler struct {
	userRegistration *users.UserRegistration
}

func NewUserHandler() *UserHandler {
	return &UserHandler{userRegistration: users.NewUserRegistration()}
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

	user := &users.User{
		Username: request.Username,
		Email:    request.Email,
		Password: request.Password,
	}

	createdUser, err := h.userRegistration.RegisterUser(user)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	response := users.NewUserRegistrationResponse(createdUser.Username, createdUser.Email)
	utils.WriteJSON(w, http.StatusCreated, response)
}
