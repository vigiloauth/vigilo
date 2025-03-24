package service

import (
	"fmt"
	"net/url"

	domain "github.com/vigiloauth/vigilo/internal/domain/authorization"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

var _ domain.AuthorizationService = (*AuthorizationServiceImpl)(nil)

type AuthorizationServiceImpl struct {
	codeService    authz.AuthorizationCodeService
	consentService consent.ConsentService
}

func NewAuthorizationServiceImpl(
	codeService authz.AuthorizationCodeService,
	consentService consent.ConsentService,
) *AuthorizationServiceImpl {
	return &AuthorizationServiceImpl{
		codeService:    codeService,
		consentService: consentService,
	}
}

// AuthorizeClient handles the authorization logic for a client request.
//
// Parameters:
//
//   - userID: The ID of the user attempting to authorize the client.
//   - clientID: The ID of the client requesting authorization.
//   - redirectURI: The URI to redirect the user to after authorization.
//   - scope: The requested authorization scopes.
//   - state: An optional state parameter for maintaining request state between the client and the authorization server.
//   - consentApproved: A boolean indicating whether the user has already approved consent for the requested scopes.
//
// Returns:
//
//   - bool: A boolean indicating whether authorization was successful.
//   - string: The redirect URL, or an empty string if authorization failed.
//   - string: An error message, or an empty string if authorization was successful.
//
// This method performs the following steps:
//  1. Checks if the user is authenticated.
//  2. Verifies user consent if required or if already approved.
//  3. Generates an authorization code if authorization is successful.
//  4. Constructs the redirect URL with the authorization code or error parameters.
//  5. Returns the success status, redirect URL and any error messages.
//
// Errors:
//
//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
func (h *AuthorizationServiceImpl) AuthorizeClient(
	userID string,
	clientID string,
	redirectURI string,
	scope string,
	state string,
	consentApproved bool,
) (string, error) {
	consentRequired, err := h.consentService.CheckUserConsent(userID, clientID, scope)
	if err != nil {
		return "", errors.NewAccessDeniedError()
	}

	if !consentApproved && consentRequired {
		consentURL := h.buildConsentURL(clientID, redirectURI, scope, state)
		return "", errors.NewConsentRequiredError(consentURL)
	}

	if consentApproved && !consentRequired {
		return "", errors.NewAccessDeniedError()
	}

	code, err := h.codeService.GenerateAuthorizationCode(userID, clientID, redirectURI, scope)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to generate authorization code")
		return "", wrappedErr
	}

	return h.buildRedirectURL(redirectURI, code, state), nil
}

func (h *AuthorizationServiceImpl) buildConsentURL(clientID, redirectURI, scope, state string) string {
	URL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s",
		web.OAuthEndpoints.Consent,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
	)

	if state != "" {
		URL = fmt.Sprintf("%s&state=%s", URL, url.QueryEscape(state))
	}

	return URL
}

func (h *AuthorizationServiceImpl) buildRedirectURL(redirectURI, code, state string) string {
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	return redirectURL
}
