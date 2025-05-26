package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	authzCodeMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	clientMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	sessionMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
	consentMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestClientAuthorization_Authorize(t *testing.T) {
	ctx := context.Background()

	mockValidator := &clientMocks.MockClientValidator{}
	mockManager := &clientMocks.MockClientManager{}
	mockSession := &sessionMocks.MockSessionManager{}
	mockConsent := &consentMocks.MockUserConsentService{}
	mockIssuer := &authzCodeMocks.MockAuthorizationCodeIssuer{}

	sut := NewClientAuthorization(
		mockValidator,
		mockManager,
		mockSession,
		mockConsent,
		mockIssuer,
	)

	t.Run("happy path", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return "userID", nil
		}
		mockSession.GetUserAuthenticationTimeFunc = func(ctx context.Context, r *http.Request) (int64, error) {
			return int64(1800), nil
		}
		mockConsent.CheckUserConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return true, nil
		}
		mockIssuer.IssueAuthorizationCodeFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
			return "code", nil
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.NoError(t, err)
		assert.Contains(t, redirectURL, "code")
	})

	t.Run("should return error if client request URI validation fails", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{ClientID: "valid-client-id"}

		mockManagerCall := 0
		mockValidatorCall := 0

		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			mockManagerCall++
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			mockValidatorCall++
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			mockValidatorCall++
			return errors.New(errors.ErrCodeInvalidRequest, "invalid request URI")
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Empty(t, redirectURL)
		assert.Error(t, err)
		assert.GreaterOrEqual(t, mockManagerCall, 0)
		assert.GreaterOrEqual(t, mockValidatorCall, 1)
	})

	t.Run("should return consent redirect URL if user consent is required", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:        "valid-client-id",
			UserID:          "user-id",
			ConsentApproved: false,
			RedirectURI:     "http://example.com/callback",
		}

		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return req.UserID, nil
		}
		mockSession.GetUserAuthenticationTimeFunc = func(ctx context.Context, r *http.Request) (int64, error) {
			return int64(1800), nil
		}
		mockConsent.CheckUserConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return false, nil
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Contains(t, redirectURL, "consent")
		assert.NoError(t, err)
	})

	t.Run("should force login if prompt is set to login", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptLogin,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Contains(t, redirectURL, "authenticate")
		assert.NoError(t, err)
	})

	t.Run("should return login required error if user is not authenticated", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return "", errors.New(errors.ErrCodeNotFound, "user ID not present")
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Contains(t, redirectURL, "authentication+required+to+continue")
		assert.NoError(t, err)
	})

	t.Run("unauthorized error is returned when authorization request validation fails", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return errors.New(errors.ErrCodeUnauthorized, "invalid client")
		}

		_, err := sut.Authorize(ctx, req)

		assert.Error(t, err)
		assert.Equal(t, errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized], errors.SystemErrorCode(err))
	})

	t.Run("unauthorized client error is returned when client doest not exist by ID", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, errors.New(errors.ErrCodeClientNotFound, "client not found by ID")
		}

		_, err := sut.Authorize(ctx, req)

		assert.Error(t, err)
		assert.Equal(t, errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient], errors.SystemErrorCode(err))
	})

	t.Run("login redirect URL is returned when user is not authenticated", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return "", nil
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Contains(t, redirectURL, "authenticate")
		assert.NoError(t, err)
	})

	t.Run("consent required error is returned when rejecting missing consent", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return "userID", nil
		}
		mockSession.GetUserAuthenticationTimeFunc = func(ctx context.Context, r *http.Request) (int64, error) {
			return int64(1800), nil
		}
		mockConsent.CheckUserConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return false, errors.New(errors.ErrCodeConsentRequired, "consent required")
		}

		redirectURL, err := sut.Authorize(ctx, req)

		assert.Contains(t, redirectURL, "consent")
		assert.NoError(t, err)
	})

	t.Run("internal server error should be returned when issuing the authorization code fails", func(t *testing.T) {
		req := &client.ClientAuthorizationRequest{
			ClientID:    "valid-client-id",
			Prompt:      constants.PromptNone,
			RedirectURI: "http://example.com/callback",
		}
		mockManager.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return &client.Client{}, nil
		}
		mockValidator.ValidateAuthorizationRequestFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockValidator.ValidateClientRequestURIFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
			return nil
		}
		mockSession.GetUserIDFromSessionFunc = func(ctx context.Context, r *http.Request) (string, error) {
			return "userID", nil
		}
		mockSession.GetUserAuthenticationTimeFunc = func(ctx context.Context, r *http.Request) (int64, error) {
			return int64(1800), nil
		}
		mockConsent.CheckUserConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return true, nil
		}
		mockIssuer.IssueAuthorizationCodeFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
			return "", errors.NewInternalServerError()
		}

		_, err := sut.Authorize(ctx, req)

		assert.Error(t, err)
		assert.Equal(t, errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError], errors.SystemErrorCode(err))
	})
}
