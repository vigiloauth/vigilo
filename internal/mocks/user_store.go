package mocks

import "github.com/vigiloauth/vigilo/internal/users"

// MockUserStore is a mock implementation of the users.UserStore interface.
type MockUserStore struct {
	// AddUserFunc is a mock function for the AddUser method.
	AddUserFunc func(user *users.User) error

	// GetUserFunc is a mock function for the GetUser method.
	GetUserFunc func(value string) *users.User

	// DeleteUserFunc is a mock function for the DeleteUser method.
	DeleteUserFunc func(value string) error

	// UpdateUserFunc is a mock function for the UpdateUser method.
	UpdateUserFunc func(user *users.User) error
}

// AddUser calls the mock AddUserFunc.
func (m *MockUserStore) AddUser(user *users.User) error {
	return m.AddUserFunc(user)
}

// GetUser calls the mock GetUserFunc.
func (m *MockUserStore) GetUser(value string) *users.User {
	return m.GetUserFunc(value)
}

// DeleteUser calls the mock DeleteUserFunc.
func (m *MockUserStore) DeleteUser(value string) error {
	return m.DeleteUserFunc(value)
}

// UpdateUser calls the mock UpdateUserFunc.
func (m *MockUserStore) UpdateUser(user *users.User) error {
	return m.UpdateUserFunc(user)
}
