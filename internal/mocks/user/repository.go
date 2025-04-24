package mocks

import (
	"context"

	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

var _ user.UserRepository = (*MockUserRepository)(nil)

type MockUserRepository struct {
	AddUserFunc                          func(ctx context.Context, user *user.User) error
	GetUserByIDFunc                      func(ctx context.Context, userID string) (*user.User, error)
	DeleteUserByIDFunc                   func(ctx context.Context, userID string) error
	UpdateUserFunc                       func(ctx context.Context, user *user.User) error
	GetUserByEmailFunc                   func(ctx context.Context, email string) (*user.User, error)
	GetUserByUsernameFunc                func(ctx context.Context, username string) (*user.User, error)
	FindUnverifiedUsersOlderThanWeekFunc func(ctx context.Context) ([]*user.User, error)
}

func (m *MockUserRepository) AddUser(ctx context.Context, user *user.User) error {
	return m.AddUserFunc(ctx, user)
}

func (m *MockUserRepository) GetUserByID(ctx context.Context, userID string) (*user.User, error) {
	return m.GetUserByIDFunc(ctx, userID)
}

func (m *MockUserRepository) DeleteUserByID(ctx context.Context, userID string) error {
	return m.DeleteUserByIDFunc(ctx, userID)
}

func (m *MockUserRepository) UpdateUser(ctx context.Context, user *user.User) error {
	return m.UpdateUserFunc(ctx, user)
}

func (m *MockUserRepository) GetUserByEmail(ctx context.Context, email string) (*user.User, error) {
	return m.GetUserByEmailFunc(ctx, email)
}

func (m *MockUserRepository) GetUserByUsername(ctx context.Context, username string) (*user.User, error) {
	return m.GetUserByUsernameFunc(ctx, username)
}

func (m *MockUserRepository) FindUnverifiedUsersOlderThanWeek(ctx context.Context) ([]*user.User, error) {
	return m.FindUnverifiedUsersOlderThanWeekFunc(ctx)
}
