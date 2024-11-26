package users

type UserStore interface {
	AddUser(user User) error
	GetUser(value string) (User, bool)
	DeleteUser(value string) error
}
