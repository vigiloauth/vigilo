package users

type User struct {
	ID       string
	Username string
	Email    string
	Password string
}

type UserRegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (req *UserRegistrationRequest) Validate() error {
	if req.Username == "" || len(req.Username) == 0 {
		return &EmptyInputError{Message: "Username is empty"}
	}

	if req.Email == "" || len(req.Email) == 0 {
		return &EmptyInputError{Message: "Email is empty"}
	}

	if req.Password == "" || len(req.Password) == 0 {
		return &EmptyInputError{Message: "Password is empty"}
	}

	return nil
}

type UserRegistrationResponse struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func NewUserRegistrationResponse(username, email string) *UserRegistrationResponse {
	return &UserRegistrationResponse{Username: username, Email: email}
}
