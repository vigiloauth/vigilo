package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mLoginRepo "github.com/vigiloauth/vigilo/internal/mocks/login"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	testIPAddress       string = "127.001.00"
	testRequestMetadata string = "request_metadata"
	testUserAgent       string = "user_agent"
	testRequestDetails  string = "request_details"
	testUserID          string = "testUserID"
	testUsername        string = "testUsername"
	testPassword        string = "testPassword"
	testEmail           string = "test@email.com"
)

func TestLoginService_SaveLoginAttempt(t *testing.T) {
	mockUserRepository := &mUserRepo.MockUserRepository{}
	mockLoginAttemptRepo := &mLoginRepo.MockLoginAttemptRepository{}

	t.Run("Success", func(t *testing.T) {
		attempt := user.NewUserLoginAttempt(
			testIPAddress,
			testRequestMetadata,
			testRequestDetails,
			testUserAgent,
		)
		mockLoginAttemptRepo.SaveLoginAttemptFunc = func(attempt *user.UserLoginAttempt) error { return nil }

		service := NewLoginAttemptService(mockUserRepository, mockLoginAttemptRepo)
		err := service.SaveLoginAttempt(attempt)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when database error occurs", func(t *testing.T) {
		attempt := user.NewUserLoginAttempt(
			testIPAddress,
			testRequestMetadata,
			testRequestDetails,
			testUserAgent,
		)

		mockLoginAttemptRepo.SaveLoginAttemptFunc = func(attempt *user.UserLoginAttempt) error {
			return errors.NewInternalServerError()
		}

		service := NewLoginAttemptService(mockUserRepository, mockLoginAttemptRepo)
		err := service.SaveLoginAttempt(attempt)

		assert.Error(t, err)
	})
}

func TestLoginService_GetLoginAttempts(t *testing.T) {
	mockUserRepository := &mUserRepo.MockUserRepository{}
	mockLoginAttemptRepo := &mLoginRepo.MockLoginAttemptRepository{}

	t.Run("GetLoginAttempts return a slice of UserLoginAttempts", func(t *testing.T) {
		mockLoginAttemptRepo.GetLoginAttemptsFunc = func(userID string) []*user.UserLoginAttempt {
			return []*user.UserLoginAttempt{
				user.NewUserLoginAttempt(
					testIPAddress,
					testRequestMetadata,
					testRequestDetails,
					testUserAgent,
				),
			}
		}

		service := NewLoginAttemptService(mockUserRepository, mockLoginAttemptRepo)
		response := service.GetLoginAttempts(testUserID)

		assert.Equal(t, 1, len(response))
	})

	t.Run("GetLoginAttempts returns an empty slice", func(t *testing.T) {
		mockLoginAttemptRepo.GetLoginAttemptsFunc = func(userID string) []*user.UserLoginAttempt {
			return []*user.UserLoginAttempt{}
		}

		service := NewLoginAttemptService(mockUserRepository, mockLoginAttemptRepo)
		response := service.GetLoginAttempts(testUserID)

		assert.Empty(t, response)
	})
}

func TestLoginService_HandleFailedLoginAttempt(t *testing.T) {
	t.Run("Failed login attempt is successfully stored", func(t *testing.T) {
		loginUser := &user.User{
			ID:              testUserID,
			Username:        testUsername,
			Password:        testPassword,
			Email:           testEmail,
			LastFailedLogin: time.Time{},
			AccountLocked:   false,
		}

		attemptSaved := false
		mockLoginRepo := &mLoginRepo.MockLoginAttemptRepository{
			SaveLoginAttemptFunc: func(attempt *user.UserLoginAttempt) error {
				attemptSaved = true
				assert.Equal(t, testUserID, attempt.UserID)
				return nil
			},
			GetLoginAttemptsFunc: func(userID string) []*user.UserLoginAttempt {
				return []*user.UserLoginAttempt{}
			},
		}

		userUpdated := false
		mockUserRepo := &mUserRepo.MockUserRepository{
			UpdateUserFunc: func(updatedUser *user.User) error {
				userUpdated = true
				assert.Equal(t, loginUser.ID, updatedUser.ID)
				assert.False(t, updatedUser.LastFailedLogin.IsZero())
				assert.False(t, updatedUser.AccountLocked)
				return nil
			},
		}

		service := NewLoginAttemptService(mockUserRepo, mockLoginRepo)
		attempt := user.NewUserLoginAttempt(
			testIPAddress,
			testRequestMetadata,
			testRequestDetails,
			testUserAgent,
		)
		attempt.UserID = testUserID
		err := service.HandleFailedLoginAttempt(loginUser, attempt)

		assert.NoError(t, err)
		assert.True(t, attemptSaved)
		assert.True(t, userUpdated)
		assert.False(t, loginUser.AccountLocked)
	})

	t.Run("Account is locked after several failed login attempts", func(t *testing.T) {
		loginUser := &user.User{
			ID:              testUserID,
			Username:        testUsername,
			Password:        testPassword,
			Email:           testEmail,
			LastFailedLogin: time.Time{},
			AccountLocked:   false,
		}

		maxAttempts := 5
		previousAttempts := make([]*user.UserLoginAttempt, maxAttempts)
		for i := range maxAttempts {
			attempt := user.NewUserLoginAttempt(
				testIPAddress,
				testRequestMetadata,
				testRequestDetails,
				testUserAgent,
			)
			attempt.UserID = testUserID
			previousAttempts[i] = attempt
		}

		mockLoginRepo := &mLoginRepo.MockLoginAttemptRepository{
			SaveLoginAttemptFunc: func(attempt *user.UserLoginAttempt) error {
				return nil
			},
			GetLoginAttemptsFunc: func(userID string) []*user.UserLoginAttempt {
				return previousAttempts
			},
		}

		userLocked := false
		mockUserRepo := &mUserRepo.MockUserRepository{
			UpdateUserFunc: func(updatedUser *user.User) error {
				if updatedUser.AccountLocked {
					userLocked = true
				}
				return nil
			},
		}

		service := NewLoginAttemptService(mockUserRepo, mockLoginRepo)
		attempt := user.NewUserLoginAttempt(
			testIPAddress,
			testRequestMetadata,
			testRequestDetails,
			testUserAgent,
		)
		attempt.UserID = testUserID

		err := service.HandleFailedLoginAttempt(loginUser, attempt)

		assert.NoError(t, err)
		assert.True(t, userLocked)
		assert.True(t, loginUser.AccountLocked)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		loginUser := &user.User{
			ID:              testUserID,
			Username:        testUsername,
			Password:        testPassword,
			Email:           testEmail,
			LastFailedLogin: time.Time{},
			AccountLocked:   false,
		}

		mockLoginRepo := &mLoginRepo.MockLoginAttemptRepository{
			SaveLoginAttemptFunc: func(attempt *user.UserLoginAttempt) error {
				return nil
			},
			GetLoginAttemptsFunc: func(userID string) []*user.UserLoginAttempt {
				return []*user.UserLoginAttempt{}
			},
		}

		mockUserRepo := &mUserRepo.MockUserRepository{
			UpdateUserFunc: func(updatedUser *user.User) error {
				return errors.NewInternalServerError()
			},
		}

		service := NewLoginAttemptService(mockUserRepo, mockLoginRepo)
		attempt := user.NewUserLoginAttempt(
			testIPAddress,
			testRequestMetadata,
			testRequestDetails,
			testUserAgent,
		)
		attempt.UserID = testUserID

		err := service.HandleFailedLoginAttempt(loginUser, attempt)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update the user")
	})
}
