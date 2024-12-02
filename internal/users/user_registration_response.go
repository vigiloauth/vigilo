package users

type UserRegistrationResponse struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func NewUserRegistrationResponse(username, email string) *UserRegistrationResponse {
	return &UserRegistrationResponse{Username: username, Email: email}
}
