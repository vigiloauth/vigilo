package users

type UserStore interface {
	AddUser(user *User) error
	GetUser(value string) *User
	DeleteUser(value string) error
	UpdateUser(user *User) error
}
