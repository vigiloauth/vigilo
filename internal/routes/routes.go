package routes

import (
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func (rc *RouterConfig) getAdminRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining Admin Routes")
	handler := rc.handlerRegistry.AdminHandler()
	return RouteGroup{
		Name: "Admin Routes",
		Middleware: []func(http.Handler) http.Handler{
			rc.middleware.AuthMiddleware(),
			rc.middleware.WithRole(constants.AdminRole),
		},
		Routes: []Route{
			NewRoute().
				SetMethods(http.MethodGet).
				SetPattern(web.AdminEndpoints.GetAuditEvents).
				SetHandler(handler.GetAuditEvents).
				SetDescription("Get audit events").
				Build(),
		},
	}
}

func (rc *RouterConfig) getOIDCRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining OIDC Routes")
	handler := rc.handlerRegistry.OIDCHandler()
	return RouteGroup{
		Name: "Open ID Connect Routes",
		Routes: []Route{
			NewRoute().
				SetMiddleware(rc.middleware.AuthMiddleware()).
				SetMethods(http.MethodGet, http.MethodPost).
				SetPattern(web.OIDCEndpoints.UserInfo).
				SetHandler(handler.GetUserInfo).
				SetDescription("Get user info").
				Build(),

			// Public Routes (no auth required)
			NewRoute().
				SetMethods(http.MethodGet).
				SetPattern(web.OIDCEndpoints.JWKS).
				SetHandler(handler.GetJWKS).
				SetDescription("Get JSON web key sets").
				Build(),
			NewRoute().
				SetMethods(http.MethodGet).
				SetPattern(web.OIDCEndpoints.Discovery).
				SetHandler(handler.GetOpenIDConfiguration).
				SetDescription("Get OIDC configuration").
				Build(),
		},
	}
}

func (rc *RouterConfig) getClientRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining Client Routes")
	handler := rc.handlerRegistry.ClientHandler()
	urlParam := fmt.Sprintf("/{%s}", constants.ClientIDReqField)

	return RouteGroup{
		Name: "Client Routes",
		Routes: []Route{
			// Basic client registration
			NewRoute().
				SetMiddleware(rc.middleware.RequiresContentType(constants.ContentTypeJSON)).
				SetMethods(http.MethodPost).
				SetPattern(web.ClientEndpoints.Register).
				SetHandler(handler.RegisterClient).
				SetDescription("Register new client").
				Build(),

			// Client configuration management
			NewRoute().
				SetMiddleware(rc.middleware.AuthMiddleware()).
				SetMethods(http.MethodGet, http.MethodPut, http.MethodDelete).
				SetPattern(web.ClientEndpoints.ClientConfiguration + urlParam).
				SetHandler(handler.ManageClientConfiguration).
				SetDescription("Manage client configuration").
				Build(),

			// Sensitive operations with strict rate limiting
			NewRoute().
				SetMethods(http.MethodPost).
				SetMiddleware(rc.middleware.AuthMiddleware(), rc.middleware.RequiresContentType(constants.ContentTypeJSON)).
				SetPattern(web.ClientEndpoints.RegenerateSecret + urlParam).
				SetHandler(handler.RegenerateSecret).
				SetDescription("Regenerate client secret").
				SetMiddleware(rc.middleware.StrictRateLimit).
				Build(),
		},
	}
}

func (rc *RouterConfig) getUserRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining User Routes")
	handler := rc.handlerRegistry.UserHandler()
	return RouteGroup{
		Name: "User Routes",
		Routes: []Route{
			NewRoute().
				SetMiddleware(rc.middleware.AuthMiddleware()).
				SetMethods(http.MethodPost).
				SetPattern(web.UserEndpoints.Logout).
				SetHandler(handler.Logout).
				SetDescription("User logout").
				Build(),

			// Public Routes (no auth required)
			NewRoute().
				SetMethods(http.MethodGet).
				SetPattern(web.UserEndpoints.Verify).
				SetHandler(handler.VerifyAccount).
				SetDescription("User account verification").
				Build(),
			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.UserEndpoints.Registration).
				SetHandler(handler.Register).
				SetDescription("User registration").
				Build(),
			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.UserEndpoints.Login).
				SetHandler(handler.Login).
				SetDescription("Basic user authentication").
				Build(),
			NewRoute().
				SetMethods(http.MethodPatch).
				SetPattern(web.UserEndpoints.ResetPassword).
				SetHandler(handler.ResetPassword).
				SetDescription("User password reset").
				Build(),

			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.OAuthEndpoints.Authenticate).
				SetHandler(handler.OAuthLogin).
				SetDescription("OAuth user authentication").
				Build(),
		},
	}
}

func (rc *RouterConfig) getConsentRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining User Consent Routes")
	handler := rc.handlerRegistry.OAuthHandler()
	return RouteGroup{
		Name: "OAuth Routes",
		Middleware: []func(http.Handler) http.Handler{
			rc.middleware.RequiresContentType(constants.ContentTypeJSON),
		},
		Routes: []Route{
			NewRoute().
				SetMethods(http.MethodGet, http.MethodPost).
				SetPattern(web.OAuthEndpoints.UserConsent).
				SetHandler(handler.UserConsent).
				SetDescription("Manage user consent").
				Build(),
		},
	}
}

func (rc *RouterConfig) getAuthorizationRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining Authorization Routes")
	handler := rc.handlerRegistry.AuthorizationHandler()
	return RouteGroup{
		Name: "Authorization Handler",
		Routes: []Route{
			NewRoute().
				SetMiddleware(rc.middleware.RequiresContentType(constants.ContentTypeJSON)).
				SetMethods(http.MethodGet).
				SetPattern(web.OAuthEndpoints.Authorize).
				SetHandler(handler.AuthorizeClient).
				SetDescription("Client authorization").
				Build(),
		},
	}
}

func (rc *RouterConfig) getTokenRoutes() RouteGroup {
	rc.logger.Debug(rc.module, "", "Defining Token Routes")
	handler := rc.handlerRegistry.TokenHandler()
	return RouteGroup{
		Name: "Token Handler",
		Middleware: []func(http.Handler) http.Handler{
			rc.middleware.RequiresContentType(constants.ContentTypeFormURLEncoded),
		},
		Routes: []Route{
			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.OAuthEndpoints.Token).
				SetHandler(handler.IssueTokens).
				SetDescription("Token issuance").
				Build(),
			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.OAuthEndpoints.IntrospectToken).
				SetHandler(handler.IntrospectToken).
				SetDescription("Token introspection").
				Build(),
			NewRoute().
				SetMethods(http.MethodPost).
				SetPattern(web.OAuthEndpoints.RevokeToken).
				SetHandler(handler.RevokeToken).
				SetDescription("Token revocation").
				Build(),
		},
	}
}
