package domain

import (
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

type AuthenticationService interface {
	IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes string) (*token.TokenResponse, error)
	IssueResourceOwnerToken(clientID, clientSecret, requestedGrantType, requestedScopes string, loginAttempt *user.UserLoginAttempt) (*token.TokenResponse, error)
}
