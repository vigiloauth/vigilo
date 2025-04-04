package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

// MockUserRepository is a mock implementation of the users.UserStore interface.
type MockUserRepository struct {
	// AddUserFunc is a mock function for the AddUser method.
	AddUserFunc func(user *user.User) error

	// GetUserByIDFunc is a mock function for the GetUser method.
	GetUserByIDFunc func(userID string) *user.User

	// DeleteUserByIDFunc is a mock function for the DeleteUser method.
	DeleteUserByIDFunc func(userID string) error

	// UpdateUserFunc is a mock function for the UpdateUser method.
	UpdateUserFunc func(user *user.User) error

	GetUserByEmailFunc func(email string) *user.User
}

// AddUser calls the mock AddUserFunc.
func (m *MockUserRepository) AddUser(user *user.User) error {
	return m.AddUserFunc(user)
}

// GetUser calls the mock GetUserFunc.
func (m *MockUserRepository) GetUserByID(userID string) *user.User {
	return m.GetUserByIDFunc(userID)
}

// DeleteUserByID calls the mock DeleteUserByIDFunc.
func (m *MockUserRepository) DeleteUserByID(userID string) error {
	return m.DeleteUserByIDFunc(userID)
}

// UpdateUser calls the mock UpdateUserFunc.
func (m *MockUserRepository) UpdateUser(user *user.User) error {
	return m.UpdateUserFunc(user)
}

func (m *MockUserRepository) GetUserByEmail(email string) *user.User {
	return m.GetUserByEmailFunc(email)
}
