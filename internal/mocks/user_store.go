package mocks

import "github.com/vigiloauth/vigilo/internal/users"

type MockUserStore struct {
	AddUserFunc    func(user *users.User) error
	GetUserFunc    func(value string) *users.User
	DeleteUserFunc func(value string) error
	UpdateUserFunc func(user *users.User) error
}

func (m *MockUserStore) AddUser(user *users.User) error {
	return m.AddUserFunc(user)
}

func (m *MockUserStore) GetUser(value string) *users.User {
	return m.GetUserFunc(value)
}

func (m *MockUserStore) DeleteUser(value string) error {
	return m.DeleteUserFunc(value)
}

func (m *MockUserStore) UpdateUser(user *users.User) error {
	return m.UpdateUserFunc(user)
}
