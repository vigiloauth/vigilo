package routes

import (
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/web"
)

func (ar *RouterConfig) getAdminRoutes() RouteGroup {
	handler := ar.handlerRegistry.AdminHandler()
	return RouteGroup{
		Name: "Admin Routes",
		Middleware: []func(http.Handler) http.Handler{
			ar.middleware.AuthMiddleware(),
			ar.middleware.WithRole(constants.AdminRole),
		},
		Routes: []Route{
			NewRoute().
				SetMethod(http.MethodGet).
				SetPattern(web.AdminEndpoints.GetAuditEvents).
				SetHandler(handler.GetAuditEvents).
				SetDescription("Get audit events").
				Build(),
		},
	}
}

func (ar *RouterConfig) getOIDCRoutes() RouteGroup {
	handler := ar.handlerRegistry.OIDCHandler()
	return RouteGroup{
		Name: "Open ID Connect Routes",
		Routes: []Route{
			NewRoute().
				SetMiddleware(ar.middleware.AuthMiddleware()).
				SetMethod(http.MethodGet).
				SetPattern(web.OIDCEndpoints.UserInfo).
				SetHandler(handler.GetUserInfo).
				SetDescription("Get user info").
				Build(),

			// Public Routes (no auth required)
			NewRoute().
				SetMethod(http.MethodGet).
				SetPattern(web.OIDCEndpoints.JWKS).
				SetHandler(handler.GetJWKS).
				SetDescription("Get JSON web key sets").
				Build(),
			NewRoute().
				SetMethod(http.MethodGet).
				SetPattern(web.OIDCEndpoints.Discovery).
				SetHandler(handler.GetOpenIDConfiguration).
				SetDescription("Get OIDC configuration").
				Build(),
		},
	}
}

func (ar *RouterConfig) getClientRoutes() RouteGroup {
	handler := ar.handlerRegistry.ClientHandler()
	urlParam := fmt.Sprintf("/{%s}", constants.ClientID)

	return RouteGroup{
		Name: "Client Routes",
		Middleware: []func(http.Handler) http.Handler{
			ar.middleware.AuthMiddleware(),
		},
		Routes: []Route{
			// Basic client registration
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.ClientEndpoints.Register).
				SetHandler(handler.RegisterClient).
				SetDescription("Register new client").
				Build(),

			// Client configuration management
			NewRoute().
				SetMethods(http.MethodGet, http.MethodPut, http.MethodDelete).
				SetPattern(web.ClientEndpoints.ClientConfiguration + urlParam).
				SetHandler(handler.ManageClientConfiguration).
				SetDescription("Manage client configuration").
				Build(),

			// Sensitive operations with strict rate limiting
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.ClientEndpoints.RegenerateSecret + urlParam).
				SetHandler(handler.RegenerateSecret).
				SetDescription("Regenerate client secret").
				SetMiddleware(ar.middleware.StrictRateLimit).
				Build(),
		},
	}
}

func (ar *RouterConfig) getUserRoutes() RouteGroup {
	handler := ar.handlerRegistry.UserHandler()
	return RouteGroup{
		Name: "User Routes",
		Routes: []Route{
			NewRoute().
				SetMiddleware(ar.middleware.AuthMiddleware()).
				SetMethod(http.MethodPost).
				SetPattern(web.UserEndpoints.Logout).
				SetHandler(handler.Logout).
				SetDescription("User logout").
				Build(),

			// Public Routes (no auth required)
			NewRoute().
				SetMethod(http.MethodGet).
				SetPattern(web.UserEndpoints.Verify).
				SetHandler(handler.VerifyAccount).
				SetDescription("User account verification").
				Build(),
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.UserEndpoints.Registration).
				SetHandler(handler.Register).
				SetDescription("User registration").
				Build(),
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.UserEndpoints.Login).
				SetHandler(handler.Login).
				SetDescription("Basic user authentication").
				Build(),
			NewRoute().
				SetMethod(http.MethodPatch).
				SetPattern(web.UserEndpoints.ResetPassword).
				SetHandler(handler.ResetPassword).
				SetDescription("User password reset").
				Build(),
		},
	}
}

func (ar *RouterConfig) getOAuthRoutes() RouteGroup {
	handler := ar.handlerRegistry.OAuthHandler()
	return RouteGroup{
		Name: "OAuth Routes",
		Middleware: []func(http.Handler) http.Handler{
			ar.middleware.RequiresContentType(constants.ContentTypeJSON),
		},
		Routes: []Route{
			NewRoute().
				SetMethods(http.MethodGet, http.MethodPost).
				SetPattern(web.OAuthEndpoints.UserConsent).
				SetHandler(handler.UserConsent).
				SetDescription("Manage user consent").
				Build(),
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.OAuthEndpoints.Login).
				SetHandler(handler.OAuthLogin).
				SetDescription("OAuth user authentication").
				Build(),
		},
	}
}

func (ar *RouterConfig) getAuthorizationRoutes() RouteGroup {
	handler := ar.handlerRegistry.AuthorizationHandler()
	return RouteGroup{
		Name: "Authorization Handler",
		Routes: []Route{
			NewRoute().
				SetMiddleware(ar.middleware.RequiresContentType(constants.ContentTypeJSON)).
				SetMethod(http.MethodGet).
				SetPattern(web.OAuthEndpoints.Authorize).
				SetHandler(handler.AuthorizeClient).
				SetDescription("Client authorization").
				Build(),
		},
	}
}

func (ar *RouterConfig) getTokenRoutes() RouteGroup {
	handler := ar.handlerRegistry.TokenHandler()
	return RouteGroup{
		Name: "Token Handler",
		Middleware: []func(http.Handler) http.Handler{
			ar.middleware.RequiresContentType(constants.ContentTypeForm),
		},
		Routes: []Route{
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.OAuthEndpoints.Token).
				SetHandler(handler.IssueTokens).
				SetDescription("Token issuance").
				Build(),
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.OAuthEndpoints.IntrospectToken).
				SetHandler(handler.IntrospectToken).
				SetDescription("Token introspection").
				Build(),
			NewRoute().
				SetMethod(http.MethodPost).
				SetPattern(web.OAuthEndpoints.RevokeToken).
				SetHandler(handler.RevokeToken).
				SetDescription("Token revocation").
				Build(),
		},
	}
}
