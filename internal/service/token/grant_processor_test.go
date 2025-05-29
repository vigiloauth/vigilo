package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockAuthz "github.com/vigiloauth/vigilo/v2/internal/mocks/authorization"
	mockClient "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mockUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	accessToken  string = "access-token"
	refreshToken string = "refresh-token"
	clientID     string = "client-1234"
	clientSecret string = "secret"
	requestID    string = "req-1234"
	username     string = "username"
	password     string = "testPassword"
	userID       string = "user-1234"
	code         string = "authorization_code"
	redirectURI  string = "https://callback.com"
	state        string = "test_state"
	nonce        string = "test_nonce"
	IDToken      string = "id_token"
)

func TestTokenGrantProcessor_IssueClientCredentialsToken(t *testing.T) {
	tests := []struct {
		name                string
		wantErr             bool
		expectedErr         string
		clientID            string
		clientSecret        string
		grantType           string
		scopes              types.Scope
		expectedResponse    *token.TokenResponse
		tokenIssuer         *mockToken.MockTokenIssuer
		clientAuthenticator *mockClient.MockClientAuthenticator
	}{
		{
			name:         "Success for confidential clients",
			wantErr:      false,
			expectedErr:  "",
			clientID:     clientID,
			clientSecret: clientSecret,
			grantType:    constants.ClientCredentialsGrantType,
			scopes:       types.OpenIDScope,
			expectedResponse: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
		},
		{
			name:         "Success for public clients",
			wantErr:      false,
			expectedErr:  "",
			clientID:     clientID,
			clientSecret: "",
			grantType:    constants.ClientCredentialsGrantType,
			scopes:       types.OpenIDScope,
			expectedResponse: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
		},
		{
			name:             "Unauthorized client error is returned when client does not have required grant type",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.ClientCredentialsGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have required grant type")
				},
			},
		},
		{
			name:             "Insufficient scope error is returned",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.ClientCredentialsGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeInsufficientScope, "client does not have the required scopes")
				},
			},
		},
		{
			name:             "Internal server error is returned when token issuance fails",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.ClientCredentialsGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError("")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(test.tokenIssuer, nil, test.clientAuthenticator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			response, err := sut.IssueClientCredentialsToken(
				ctx,
				test.clientID,
				test.clientSecret,
				test.grantType,
				test.scopes,
			)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, response, "Expected the response to be nil")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, response, "Expected response to not be nil")
				assert.Equal(t, test.expectedResponse.AccessToken, response.AccessToken)
				assert.Equal(t, test.expectedResponse.RefreshToken, response.RefreshToken)
				assert.Equal(t, test.expectedResponse.TokenType, response.TokenType)
				assert.Equal(t, test.expectedResponse.Scope, response.Scope)
			}
		})
	}
}

func TestTokenGrantProcessor_IssueResourceOwnerToken(t *testing.T) {
	tests := []struct {
		name                string
		wantErr             bool
		expectedErr         string
		clientID            string
		clientSecret        string
		grantType           string
		scopes              types.Scope
		loginRequest        *user.UserLoginRequest
		expectedResponse    *token.TokenResponse
		tokenIssuer         *mockToken.MockTokenIssuer
		clientAuthenticator *mockClient.MockClientAuthenticator
		userAuthenticator   *mockUser.MockUserAuthenticator
	}{
		{
			name:         "Success for confidential clients",
			wantErr:      false,
			expectedErr:  "",
			clientID:     clientID,
			clientSecret: clientSecret,
			grantType:    constants.PasswordGrantType,
			scopes:       types.OpenIDScope,
			loginRequest: &user.UserLoginRequest{Username: username, Password: password},
			expectedResponse: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
			userAuthenticator: &mockUser.MockUserAuthenticator{
				AuthenticateUserFunc: func(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error) {
					return &user.UserLoginResponse{UserID: userID}, nil
				},
			},
		},
		{
			name:         "Success for public clients",
			wantErr:      false,
			expectedErr:  "",
			clientID:     clientID,
			clientSecret: "",
			grantType:    constants.PasswordGrantType,
			scopes:       types.OpenIDScope,
			loginRequest: &user.UserLoginRequest{Username: username, Password: password},
			expectedResponse: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
			userAuthenticator: &mockUser.MockUserAuthenticator{
				AuthenticateUserFunc: func(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error) {
					return &user.UserLoginResponse{UserID: userID}, nil
				},
			},
		},
		{
			name:             "Unauthorized client error is returned when client does not have required grant type",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.PasswordGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			loginRequest:     &user.UserLoginRequest{Username: username, Password: password},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have required grant type")
				},
			},
		},
		{
			name:             "Insufficient scope error is returned",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.PasswordGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			loginRequest:     &user.UserLoginRequest{Username: username, Password: password},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeInsufficientScope, "client does not have the required scopes")
				},
			},
		},
		{
			name:             "Internal server error is returned when token issuance fails",
			wantErr:          true,
			expectedErr:      errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			clientID:         clientID,
			clientSecret:     clientSecret,
			grantType:        constants.PasswordGrantType,
			scopes:           types.OpenIDScope,
			expectedResponse: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			userAuthenticator: &mockUser.MockUserAuthenticator{
				AuthenticateUserFunc: func(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error) {
					return &user.UserLoginResponse{UserID: userID}, nil
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError("")
				},
			},
		},
		{
			name:         "Unauthorized error is returned when failing to authenticate to user",
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			loginRequest: &user.UserLoginRequest{Username: username, Password: password},
			clientID:     clientID,
			clientSecret: clientSecret,
			scopes:       types.OpenIDScope,
			grantType:    constants.PasswordGrantType,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			userAuthenticator: &mockUser.MockUserAuthenticator{
				AuthenticateUserFunc: func(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error) {
					return nil, errors.New(errors.ErrCodeUnauthorized, "invalid credentials")
				},
			},
			tokenIssuer: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(test.tokenIssuer, nil, test.clientAuthenticator, test.userAuthenticator, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			response, err := sut.IssueResourceOwnerToken(
				ctx,
				test.clientID,
				test.clientSecret,
				test.grantType,
				test.scopes,
				test.loginRequest,
			)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, response, "Expected the response to be nil")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, response, "Expected response to not be nil")
				assert.Equal(t, test.expectedResponse.AccessToken, response.AccessToken)
				assert.Equal(t, test.expectedResponse.RefreshToken, response.RefreshToken)
				assert.Equal(t, test.expectedResponse.TokenType, response.TokenType)
				assert.Equal(t, test.expectedResponse.Scope, response.Scope)
			}
		})
	}
}

func TestTokenGrantProcessor_RefreshToken(t *testing.T) { //nolint
	tests := []struct {
		name                string
		clientID            string
		clientSecret        string
		refreshToken        string
		wantErr             bool
		expectedErr         string
		expectedResp        *token.TokenResponse
		tokenIssuer         *mockToken.MockTokenIssuer
		tokenManager        *mockToken.MockTokenManager
		clientAuthenticator *mockClient.MockClientAuthenticator
	}{
		{
			name:         "Success for confidential clients",
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			wantErr:      false,
			expectedErr:  "",
			expectedResp: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{
						TokenClaims: &token.TokenClaims{
							Scopes: types.OpenIDScope,
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
								Subject:  "user",
							},
						},
					}, nil
				},
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
		},
		{
			name:         "Success for public clients",
			clientID:     clientID,
			clientSecret: "",
			refreshToken: refreshToken,
			wantErr:      false,
			expectedErr:  "",
			expectedResp: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    "bearer",
				Scope:        types.OpenIDScope,
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{
						TokenClaims: &token.TokenClaims{
							Scopes: types.OpenIDScope,
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
								Subject:  "user",
							},
						},
					}, nil
				},
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
		},
		{
			name:         "Unauthorized error is returned when client authentication fails",
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			expectedResp: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeUnauthorized, "client authentication fails")
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:         "Invalid grant error is returned when clientID does not match with the token audience",
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			expectedResp: nil,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{
						TokenClaims: &token.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: "client",
								Subject:  "user",
							},
						},
					}, nil
				},
			},
		},
		{
			name:         "Invalid grant error is returned when retrieving token data",
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			expectedResp: nil,
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return nil, errors.New(errors.ErrCodeInvalidToken, "invalid token")
				},
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			tokenIssuer: nil,
		},
		{
			name:         "Invalid request is returned when requested scopes exceed original scopes",
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeInvalidRequest],
			expectedResp: nil,
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{
						TokenClaims: &token.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
								Subject:  "user",
							},
						},
					}, nil
				},
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			tokenIssuer: nil,
		},
		{
			name:         "Internal server error is returned when issuing tokens",
			clientID:     clientID,
			clientSecret: clientSecret,
			refreshToken: refreshToken,
			wantErr:      true,
			expectedErr:  errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			expectedResp: nil,
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError("")
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{
						TokenClaims: &token.TokenClaims{
							Scopes: types.OpenIDScope,
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
								Subject:  "user",
							},
						},
					}, nil
				},
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
					return nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(test.tokenIssuer, test.tokenManager, test.clientAuthenticator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			resp, err := sut.RefreshToken(
				ctx,
				test.clientID,
				test.clientSecret,
				constants.RefreshTokenGrantType,
				test.refreshToken,
				types.OpenIDScope,
			)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, resp, "Expected the response to be nil")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, resp, "Expected response to not be nil")
				assert.Equal(t, test.expectedResp.AccessToken, resp.AccessToken)
				assert.Equal(t, test.expectedResp.RefreshToken, resp.RefreshToken)
				assert.Equal(t, test.expectedResp.TokenType, resp.TokenType)
				assert.Equal(t, test.expectedResp.Scope, resp.Scope)
			}
		})
	}
}

func TestTokenGrantProcessor_ExchangeAuthorizationCode(t *testing.T) {
	tests := []struct {
		name          string
		wantErr       bool
		expectedErr   string
		request       *token.TokenRequest
		expectedRes   *token.TokenResponse
		issuer        *mockToken.MockTokenIssuer
		authorization *mockAuthz.MockAuthorizationService
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			expectedRes: &token.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				IDToken:      IDToken,
				TokenType:    token.BearerToken,
				Scope:        types.OpenIDScope,
			},
			request: &token.TokenRequest{
				GrantType:         constants.AuthorizationCodeGrantType,
				AuthorizationCode: code,
				RedirectURI:       redirectURI,
				ClientID:          clientID,
				State:             state,
			},
			authorization: &mockAuthz.MockAuthorizationService{
				AuthorizeTokenExchangeFunc: func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
					return &authzCode.AuthorizationCodeData{
						UserID:                 userID,
						ClientID:               clientID,
						RedirectURI:            redirectURI,
						Scope:                  types.OpenIDScope,
						Code:                   code,
						Nonce:                  nonce,
						AccessTokenHash:        "access_token_hash",
						Used:                   false,
						UserAuthenticationTime: time.Now(),
					}, nil
				},
				UpdateAuthorizationCodeFunc: func(ctx context.Context, authzCode *authzCode.AuthorizationCodeData) error {
					return nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, refreshToken, nil
				},
				IssueIDTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, nonce string, acrValues string, authTime time.Time) (string, error) {
					return IDToken, nil
				},
			},
		},
		{
			name:        "Invalid grant error is returned when the authorization code has already been used",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			request: &token.TokenRequest{
				GrantType:         constants.AuthorizationCodeGrantType,
				AuthorizationCode: code,
				RedirectURI:       redirectURI,
				ClientID:          clientID,
				State:             state,
			},
			authorization: &mockAuthz.MockAuthorizationService{
				AuthorizeTokenExchangeFunc: func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
					return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code has already been used")
				},
			},
			issuer: nil,
		},
		{
			name:        "Internal server error is returned when token issuance fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request: &token.TokenRequest{
				GrantType:         constants.AuthorizationCodeGrantType,
				AuthorizationCode: code,
				RedirectURI:       redirectURI,
				ClientID:          clientID,
				State:             state,
			},
			authorization: &mockAuthz.MockAuthorizationService{
				AuthorizeTokenExchangeFunc: func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
					return &authzCode.AuthorizationCodeData{
						UserID:                 userID,
						ClientID:               clientID,
						RedirectURI:            redirectURI,
						Scope:                  types.OpenIDScope,
						Code:                   code,
						Nonce:                  nonce,
						AccessTokenHash:        "access_token_hash",
						Used:                   false,
						UserAuthenticationTime: time.Now(),
					}, nil
				},
				UpdateAuthorizationCodeFunc: func(ctx context.Context, authzCode *authzCode.AuthorizationCodeData) error {
					return nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError("")
				},
			},
		},
		{
			name:        "Internal server error is returned when ID token issuance fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request: &token.TokenRequest{
				GrantType:         constants.AuthorizationCodeGrantType,
				AuthorizationCode: code,
				RedirectURI:       redirectURI,
				ClientID:          clientID,
				State:             state,
			},
			authorization: &mockAuthz.MockAuthorizationService{
				AuthorizeTokenExchangeFunc: func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
					return &authzCode.AuthorizationCodeData{
						UserID:                 userID,
						ClientID:               clientID,
						RedirectURI:            redirectURI,
						Scope:                  types.OpenIDScope,
						Code:                   code,
						Nonce:                  nonce,
						AccessTokenHash:        "access_token_hash",
						Used:                   false,
						UserAuthenticationTime: time.Now(),
					}, nil
				},
				UpdateAuthorizationCodeFunc: func(ctx context.Context, authzCode *authzCode.AuthorizationCodeData) error {
					return nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return accessToken, redirectURI, nil
				},
				IssueIDTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, nonce string, acrValues string, authTime time.Time) (string, error) {
					return "", errors.NewInternalServerError("")
				},
			},
		},
		{
			name:        "Invalid client error is returned when client does not exist by ID",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInvalidClient],
			request: &token.TokenRequest{
				GrantType:         constants.AuthorizationCodeGrantType,
				AuthorizationCode: code,
				RedirectURI:       redirectURI,
				ClientID:          clientID,
				State:             state,
			},
			authorization: &mockAuthz.MockAuthorizationService{
				AuthorizeTokenExchangeFunc: func(ctx context.Context, tokenRequest *token.TokenRequest) (*authzCode.AuthorizationCodeData, error) {
					return nil, errors.New(errors.ErrCodeInvalidClient, "invalid client credentials")
				},
			},
			issuer: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(test.issuer, nil, nil, nil, test.authorization)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			res, err := sut.ExchangeAuthorizationCode(ctx, test.request)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, res, "Expected the result to be nil")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, res, "Expected the result to not be nil")
				assert.Equal(t, test.expectedRes.AccessToken, res.AccessToken)
				assert.Equal(t, test.expectedRes.RefreshToken, res.RefreshToken)
				assert.Equal(t, test.expectedRes.TokenType, res.TokenType)
				assert.Equal(t, test.expectedRes.Scope, res.Scope)
				assert.Equal(t, test.expectedRes.IDToken, res.IDToken)
			}
		})
	}
}

func TestTokenGrantProcessor_IntrospectToken(t *testing.T) {
	tests := []struct {
		name                string
		wantErr             bool
		expectedErr         string
		useBasicAuth        bool
		clientAuthenticator *mockClient.MockClientAuthenticator
		tokenManager        *mockToken.MockTokenManager
	}{
		{
			name:         "Success when client uses basic auth",
			wantErr:      false,
			expectedErr:  "",
			useBasicAuth: true,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				IntrospectFunc: func(ctx context.Context, tokenStr string) *token.TokenIntrospectionResponse {
					return &token.TokenIntrospectionResponse{
						Active: true,
					}
				},
			},
		},
		{
			name:         "Success when client uses bearer token",
			wantErr:      false,
			expectedErr:  "",
			useBasicAuth: false,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				IntrospectFunc: func(ctx context.Context, tokenStr string) *token.TokenIntrospectionResponse {
					return &token.TokenIntrospectionResponse{
						Active: true,
					}
				},
			},
		},
		{
			name:        "Unauthorized client error is returned when authentication fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "invalid credentials")
				},
			},
		},
		{
			name:        "Insufficient scope error is returned when client does not have the required scope",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return errors.New(errors.ErrCodeInsufficientScope, "insufficient scopes")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(nil, test.tokenManager, test.clientAuthenticator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			r := httptest.NewRequest(
				http.MethodGet,
				"https://localhost/test",
				nil,
			)

			if test.useBasicAuth {
				r.SetBasicAuth(clientID, clientSecret)
			} else {
				r.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+"token")
			}

			res, err := sut.IntrospectToken(ctx, r, "token")

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, res, "Expected the result to be nil")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, res, "Expected the result to not be nil")
			}
		})
	}
}

func TestTokenGrantProcessor_RevokeToken(t *testing.T) {
	tests := []struct {
		name                string
		wantErr             bool
		expectedErr         string
		useBasicAuth        bool
		clientAuthenticator *mockClient.MockClientAuthenticator
		tokenManager        *mockToken.MockTokenManager
	}{
		{
			name:         "Success when client uses basic auth",
			wantErr:      false,
			expectedErr:  "",
			useBasicAuth: true,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				RevokeFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
		},
		{
			name:         "Success when client uses bearer token",
			wantErr:      false,
			expectedErr:  "",
			useBasicAuth: false,
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				RevokeFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
		},
		{
			name:        "Unauthorized client error is returned when authentication fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "invalid credentials")
				},
			},
		},
		{
			name:        "Internal error is returned when revocation fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return nil
				},
			},
			tokenManager: &mockToken.MockTokenManager{
				RevokeFunc: func(ctx context.Context, tokenStr string) error {
					return errors.NewInternalServerError("")
				},
			},
		},
		{
			name:        "Insufficient scope error is returned when client does not have the required scope",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
			clientAuthenticator: &mockClient.MockClientAuthenticator{
				AuthenticateRequestFunc: func(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
					return errors.New(errors.ErrCodeInsufficientScope, "insufficient scopes")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenGrantProcessor(nil, test.tokenManager, test.clientAuthenticator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)
			r := httptest.NewRequest(
				http.MethodGet,
				"https://localhost/test",
				nil,
			)

			if test.useBasicAuth {
				r.SetBasicAuth(clientID, clientSecret)
			} else {
				r.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+"token")
			}

			err := sut.RevokeToken(ctx, r, "token")

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}
