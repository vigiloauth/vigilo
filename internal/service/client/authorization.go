package service

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

var _ client.ClientAuthorization = (*clientAuthorization)(nil)

type clientAuthorization struct {
	validator client.ClientValidator
	manager   client.ClientManager
	session   session.SessionManager
	consent   consent.UserConsentService
	issuer    authzCode.AuthorizationCodeIssuer

	logger *config.Logger
	module string
}

func NewClientAuthorization(
	validator client.ClientValidator,
	manager client.ClientManager,
	session session.SessionManager,
	consent consent.UserConsentService,
	issuer authzCode.AuthorizationCodeIssuer,
) client.ClientAuthorization {
	return &clientAuthorization{
		validator: validator,
		manager:   manager,
		session:   session,
		consent:   consent,
		issuer:    issuer,

		logger: config.GetServerConfig().Logger(),
		module: "Client Authorization",
	}
}

// Authorize handles the authorization logic for a client request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - req *ClientAuthorizationRequest: The client authorization request.
//
// Returns:
//   - string: The redirect URL, or an empty string if authorization failed.
//   - error: An error message, if any.
//
// Errors:
//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
func (c *clientAuthorization) Authorize(
	ctx context.Context,
	req *client.ClientAuthorizationRequest,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	if req.RequestURI != "" {
		return web.BuildErrorURL(
			errors.ErrCodeRequestURINotSupported,
			"request URIs are not currently supported",
			req.State,
			req.RedirectURI,
		), nil
	}

	if req.RequestObject != "" {
		return web.BuildErrorURL(
			errors.ErrCodeRequestObjectNotSupported,
			"request objects are not currently supported",
			req.State,
			req.RedirectURI,
		), nil
	}

	if req.ResponseType == "" {
		return web.BuildErrorURL(
			errors.ErrCodeInvalidRequest,
			"response_type is required",
			req.State,
			req.RedirectURI,
		), nil
	}

	client, err := c.manager.GetClientByID(ctx, req.ClientID)
	if err != nil {
		c.logger.Error(c.module, requestID, "[Authorize]: Failed to get client by ID: %v", err)
		return "", errors.New(errors.ErrCodeUnauthorizedClient, "invalid client credentials")
	}

	req.Client = client
	if err := c.validator.ValidateAuthorizationRequest(ctx, req); err != nil {
		c.logger.Error(c.module, requestID, "[Authorize]: Authorization request validation failed: %v", err)
		return "", errors.Wrap(err, "", "failed to authorize request")
	}

	if c.shouldForceLogin(ctx, req) {
		return c.buildLoginRedirectURL(req), nil
	}

	userID, isAuthenticated := c.isUserAuthenticated(ctx, requestID, req.HTTPRequest)
	if c.shouldRejectUnauthenticatedUser(req, isAuthenticated) {
		return c.buildLoginRequiredErrorURL(req), nil
	}
	if !isAuthenticated {
		return c.buildLoginRedirectURL(req), nil
	}

	req.UserID = userID
	req.UserAuthenticationTime = c.getUserAuthenticationTime(ctx, requestID, req.HTTPRequest)

	if c.shouldRejectMissingConsent(ctx, req, isAuthenticated) {
		return c.buildConsentRequiredErrorURL(req), nil
	}
	if url := c.handleUserConsent(ctx, req); url != "" {
		return url, nil
	}

	authCode, err := c.issuer.IssueAuthorizationCode(ctx, req)
	if err != nil {
		c.logger.Error(requestID, c.module, "[Authorize]: Failed to issue authorization code: %v", err)
		return "", errors.New(errors.ErrCodeInternalServerError, "failed to issue authorization code")
	}

	return c.buildRedirectURL(req.RedirectURI, authCode, req.State, req.Nonce), nil
}

func (c *clientAuthorization) shouldForceLogin(ctx context.Context, req *client.ClientAuthorizationRequest) bool {
	if req.Prompt == constants.PromptLogin {
		return true
	}

	maxAge := req.MaxAge
	if maxAge != "" {
		if maxAge == "0" {
			return true
		}

		maxAgeSeconds, err := strconv.ParseInt(maxAge, 10, 64)
		if err != nil {
			c.logger.Warn(c.module, utils.GetRequestID(ctx), "[shouldForceLogin]: Failed to parse max_age: %v", err)
			return true
		}

		lastAuthTime, err := c.session.GetUserAuthenticationTime(ctx, req.HTTPRequest)
		if err != nil {
			return true
		}

		currentTime := time.Now().Unix()
		secondsSinceLastLogin := currentTime - lastAuthTime
		c.logger.Debug(c.module, utils.GetRequestID(ctx), "[shouldForceLogin]: seconds since last login: %d", secondsSinceLastLogin)

		if secondsSinceLastLogin > maxAgeSeconds {
			return true
		}
	}

	return false
}

func (c *clientAuthorization) buildLoginRedirectURL(req *client.ClientAuthorizationRequest) string {
	return web.BuildRedirectURL(
		req.ClientID,
		req.RedirectURI,
		req.Scope.String(),
		req.ResponseType,
		req.State,
		req.Nonce,
		req.Prompt,
		req.Display,
		req.ACRValues,
		domain.SerializeClaims(req.ClaimsRequest),
		"authenticate",
	)
}

func (c *clientAuthorization) buildLoginRequiredErrorURL(req *client.ClientAuthorizationRequest) string {
	return web.BuildErrorURL(
		errors.ErrCodeLoginRequired,
		"authentication required to continue",
		req.State, req.RedirectURI,
	)
}

func (c *clientAuthorization) isUserAuthenticated(ctx context.Context, requestID string, r *http.Request) (string, bool) {
	userID, err := c.session.GetUserIDFromSession(ctx, r)
	if err != nil {
		c.logger.Warn(c.module, requestID, "[isUserAuthenticated]: User is not authenticated: %v", err)
		return "", false
	}

	if userID == "" {
		return "", false
	}

	return userID, true
}

func (c *clientAuthorization) shouldRejectUnauthenticatedUser(req *client.ClientAuthorizationRequest, isAuthenticated bool) bool {
	return req.Prompt == constants.PromptNone && !isAuthenticated
}

func (c *clientAuthorization) getUserAuthenticationTime(ctx context.Context, requestID string, r *http.Request) time.Time {
	authTime, err := c.session.GetUserAuthenticationTime(ctx, r)
	if err != nil {
		c.logger.Warn(c.module, requestID, "[getUserAuthenticationTime]: Failed to get session data: %v", err)
		return time.Time{}
	}

	if authTime < 0 {
		return time.Time{}
	}

	return time.Unix(authTime, 0)
}

func (c *clientAuthorization) shouldRejectMissingConsent(ctx context.Context, req *client.ClientAuthorizationRequest, isAuthenticated bool) bool {
	return req.Prompt == constants.PromptNone && isAuthenticated && !c.hasPreConfiguredConsent(ctx, req)
}

func (c *clientAuthorization) hasPreConfiguredConsent(ctx context.Context, req *client.ClientAuthorizationRequest) bool {
	requestID := utils.GetRequestID(ctx)
	hasConsent, err := c.consent.CheckUserConsent(ctx, req.UserID, req.ClientID, req.Scope)
	if err != nil {
		c.logger.Error(c.module, requestID, "Failed to check user consent, user=[%s]: %v", utils.TruncateSensitive(req.UserID), err)
		return false
	}

	return hasConsent
}

func (c *clientAuthorization) buildConsentRequiredErrorURL(req *client.ClientAuthorizationRequest) string {
	return web.BuildErrorURL(
		errors.ErrCodeConsentRequired,
		"consent required to continue",
		req.State, req.RedirectURI,
	)
}

func (c *clientAuthorization) handleUserConsent(ctx context.Context, req *client.ClientAuthorizationRequest) string {
	requestID := utils.GetRequestID(ctx)
	if !c.hasPreConfiguredConsent(ctx, req) {
		if !req.ConsentApproved {
			c.logger.Warn(c.module, requestID, "Consent required, redirecting to consent URL")
			consentURL := web.BuildRedirectURL(
				req.ClientID,
				req.RedirectURI,
				req.Scope.String(),
				req.ResponseType,
				req.State,
				req.Nonce,
				req.Prompt,
				req.Display,
				req.ACRValues,
				domain.SerializeClaims(req.ClaimsRequest),
				"consent",
			)

			return consentURL
		}
	}

	return ""
}

func (c *clientAuthorization) buildRedirectURL(redirectURI, code, state, nonce string) string {
	queryParams := url.Values{}
	queryParams.Add(constants.CodeURLValue, code)

	if state != "" {
		queryParams.Add(constants.StateReqField, state)
	}
	if nonce != "" {
		queryParams.Add(constants.NonceReqField, nonce)
	}

	return redirectURI + "?" + queryParams.Encode()
}
