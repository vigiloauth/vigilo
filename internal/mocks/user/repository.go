package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

var _ user.UserRepository = (*MockUserRepository)(nil)

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

	// GetUserByEmailFunc is a mock function for the GetUserByEmail method.
	GetUserByEmailFunc func(email string) *user.User

	// GetUserByUsernameFunc is a mock function for the GetUserByUsernameFunc method.
	GetUserByUsernameFunc func(username string) *user.User

	// FindUnverifiedUsersOlderThanWeekFunc is a mock function for the FindUnverifiedUsersOlderThanWeekFunc method.
	FindUnverifiedUsersOlderThanWeekFunc func() []*user.User
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

// GetUserByEmail calls the mock GetUserByEmailFunc.
func (m *MockUserRepository) GetUserByEmail(email string) *user.User {
	return m.GetUserByEmailFunc(email)
}

// GetUserByUsername calls the mock GetUserByUsernameFunc.
func (m *MockUserRepository) GetUserByUsername(username string) *user.User {
	return m.GetUserByUsernameFunc(username)
}

// FindUnverifiedUsersOlderThanWeek calls the mock FindUnverifiedUsersOlderThanWeekFunc.
func (m *MockUserRepository) FindUnverifiedUsersOlderThanWeek() []*user.User {
	return m.FindUnverifiedUsersOlderThanWeekFunc()
}
