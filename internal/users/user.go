package users

type User struct {
	ID       string
	Username string
	Email    string
	Password string
}

func NewUser(username, email, password string) *User {
	return &User{
		Username: username,
		Email:    email,
		Password: password,
	}
}
