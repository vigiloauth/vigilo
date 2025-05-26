package domain

import (
	"net/http"
	"time"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// AuthorizationCodeData represents the data associated with an authorization code.
type AuthorizationCodeData struct {
	UserID                 string
	ClientID               string
	RedirectURI            string
	Scope                  types.Scope
	Code                   string
	CodeChallenge          string
	CodeChallengeMethod    types.CodeChallengeMethod
	Nonce                  string
	AccessTokenHash        string
	Used                   bool
	CreatedAt              time.Time
	UserAuthenticationTime time.Time
	Request                *http.Request
	ClaimsRequest          *domain.ClaimsRequest
	ACRValues              string
}
