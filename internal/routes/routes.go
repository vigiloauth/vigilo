package routes

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/container"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/web"
)

type AppRouter struct {
	router     chi.Router
	middleware *middleware.Middleware
	logger     *config.Logger
	module     string

	forceHTTPS      bool
	handlerRegistry *container.HandlerRegistry
}

func NewAppRouter(
	router chi.Router,
	logger *config.Logger,
	forceHTTPS bool,
	middleware *middleware.Middleware,
	handlerRegistry *container.HandlerRegistry,
) *AppRouter {
	r := &AppRouter{
		router:          router,
		logger:          logger,
		module:          "Vigilo Identity Provider",
		forceHTTPS:      forceHTTPS,
		middleware:      middleware,
		handlerRegistry: handlerRegistry,
	}

	r.applyGlobalMiddleware()
	r.setupRoutes()
	return r
}

func (ar *AppRouter) Router() chi.Router {
	return ar.router
}

func (ar *AppRouter) applyGlobalMiddleware() {
	ar.router.Use(ar.middleware.WithContextValues)
	ar.router.Use(ar.middleware.RateLimit)
	if ar.forceHTTPS {
		ar.logger.Info(ar.module, "", "The Vigilo Identity Provider is running on HTTPS")
		ar.router.Use(ar.middleware.RedirectToHTTPS)
	} else {
		ar.logger.Warn(ar.module, "", "The Vigilo Identity Provider is running on HTTP. It is recommended to enable HTTPS in production environments")
	}
}

func (ar *AppRouter) setupRoutes() {
	ar.setupAdminRoutes()
	ar.setupOIDCRoutes()
	ar.setupClientRoutes()
	ar.setupUserRoutes()
	ar.setupOAuthRoutes()
	ar.setupAuthorizationHandler()
	ar.setupTokenRoutes()
}

func (ar *AppRouter) setupAdminRoutes() {
	adminHandler := ar.handlerRegistry.AdminHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.AuthMiddleware())
		r.Use(ar.middleware.WithRole(constants.AdminRole))
		r.Get(web.AdminEndpoints.GetAuditEvents, adminHandler.GetAuditEvents)
	})
}

func (ar *AppRouter) setupOIDCRoutes() {
	oidcHandler := ar.handlerRegistry.GetOIDCHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.AuthMiddleware())
		r.Get(web.OIDCEndpoints.UserInfo, oidcHandler.GetUserInfo)
	})
	ar.router.Get(web.OIDCEndpoints.JWKS, oidcHandler.GetJWKS)
}

func (ar *AppRouter) setupClientRoutes() {
	var clientURLParam string = fmt.Sprintf("/{%s}", constants.ClientID)
	clientHandler := ar.handlerRegistry.GetClientHandler()

	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.AuthMiddleware())
		r.Post(web.ClientEndpoints.Register, clientHandler.RegisterClient)
		r.Route(web.ClientEndpoints.ClientConfiguration, func(cr chi.Router) {
			cr.Get(clientURLParam, clientHandler.ManageClientConfiguration)
			cr.Put(clientURLParam, clientHandler.ManageClientConfiguration)
			cr.Delete(clientURLParam, clientHandler.ManageClientConfiguration)
		})

		r.Group(func(sr chi.Router) {
			sr.Use(ar.middleware.StrictRateLimit)
			sr.Post(web.ClientEndpoints.RegenerateSecret+clientURLParam, clientHandler.RegenerateSecret)
		})
	})
}

func (ar *AppRouter) setupUserRoutes() {
	userHandler := ar.handlerRegistry.UserHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.AuthMiddleware())
		r.Post(web.UserEndpoints.Logout, userHandler.Logout)
	})

	ar.router.Get(web.UserEndpoints.Verify, userHandler.VerifyAccount)
	ar.router.Post(web.UserEndpoints.Registration, userHandler.Register)
	ar.router.Post(web.UserEndpoints.Login, userHandler.Login)
	ar.router.Patch(web.UserEndpoints.ResetPassword, userHandler.ResetPassword)
}

func (ar *AppRouter) setupOAuthRoutes() {
	oauthHandler := ar.handlerRegistry.OAuthHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.RequiresContentType(constants.ContentTypeJSON))
		r.HandleFunc(web.OAuthEndpoints.UserConsent, oauthHandler.UserConsent)
		r.Post(web.OAuthEndpoints.Login, oauthHandler.OAuthLogin)
	})
}

func (ar *AppRouter) setupAuthorizationHandler() {
	authorizationHandler := ar.handlerRegistry.AuthorizationHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.RequiresContentType(constants.ContentTypeJSON))
		r.Get(web.OAuthEndpoints.Authorize, authorizationHandler.AuthorizeClient)
	})
}

func (ar *AppRouter) setupTokenRoutes() {
	tokenHandler := ar.handlerRegistry.TokenHandler()
	ar.router.Group(func(r chi.Router) {
		r.Use(ar.middleware.RequiresContentType(constants.ContentTypeForm))
		r.Group(func(pr chi.Router) {
			pr.Use(ar.middleware.RequireRequestMethod(http.MethodPost))
			pr.Post(web.OAuthEndpoints.Token, tokenHandler.IssueTokens)
			pr.Post(web.OAuthEndpoints.IntrospectToken, tokenHandler.IntrospectToken)
			pr.Post(web.OAuthEndpoints.RevokeToken, tokenHandler.RevokeToken)
		})
	})
}
