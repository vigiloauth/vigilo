package routes

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/container"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/middleware"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

const maxAge int = 300

type RouterConfig struct {
	router     chi.Router
	middleware *middleware.Middleware
	logger     *config.Logger
	module     string

	forceHTTPS           bool
	enableRequestLogging bool

	handlerRegistry *container.HandlerRegistry
}

func NewRouterConfig(
	router chi.Router,
	logger *config.Logger,
	forceHTTPS bool,
	enableRequestLogging bool,
	middleware *middleware.Middleware,
	handlerRegistry *container.HandlerRegistry,
) *RouterConfig {
	r := &RouterConfig{
		router:               router,
		logger:               logger,
		module:               "Router Config",
		forceHTTPS:           forceHTTPS,
		enableRequestLogging: enableRequestLogging,
		middleware:           middleware,
		handlerRegistry:      handlerRegistry,
	}

	return r
}

func (rc *RouterConfig) Router() chi.Router {
	return rc.router
}

func (rc *RouterConfig) Init() *RouterConfig {
	rc.logger.Debug(rc.module, "", "Registering global middleware...")
	rc.applyGlobalMiddleware()

	rc.logger.Debug(rc.module, "", "Registering error handlers...")
	rc.setupErrorHandlers()

	rc.logger.Debug(rc.module, "", "Registering route groups...")
	rc.setupRouteGroups()

	return rc
}

func (rc *RouterConfig) applyGlobalMiddleware() {
	rc.router.Use(rc.middleware.WithContextValues)
	rc.router.Use(rc.middleware.RateLimit)

	if rc.forceHTTPS {
		rc.logger.Info(rc.module, "", "The Vigilo Identity Provider is running on HTTPS")
		rc.router.Use(rc.middleware.RedirectToHTTPS)
	} else {
		rc.logger.Warn(rc.module, "", "The Vigilo Identity Provider is running on HTTP. It is recommended to enable HTTPS in production environments")
	}

	if rc.enableRequestLogging {
		rc.logger.Warn(rc.module, "", "Request logging is enabled. It is recommended to disable this in production environments.")
		rc.router.Use(rc.middleware.RequestLogger)
	}

	rc.router.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", constants.RequestIDHeader},
		ExposedHeaders:   []string{"Link", constants.RequestIDHeader},
		AllowCredentials: true,
		MaxAge:           maxAge,
	}))
}

func (rc *RouterConfig) setupErrorHandlers() {
	rc.router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		requestID := ""
		if r.Context().Value(constants.ContextKeyRequestID) != nil {
			requestID = r.Context().Value(constants.ContextKeyRequestID).(string)
		}
		rc.logger.Warn(rc.module, requestID, "Resource not found: %s", r.URL)
		web.WriteError(w, errors.New(errors.ErrCodeResourceNotFound, "resource not found"))
	})

	rc.router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		requestID := ""
		if r.Context().Value(constants.ContextKeyRequestID) != nil {
			requestID = r.Context().Value(constants.ContextKeyRequestID).(string)
		}
		rc.logger.Warn(rc.module, requestID, "Method not allowed: %s", r.Method)
		web.WriteError(w, errors.New(errors.ErrCodeMethodNotAllowed, "method not allowed"))
	})
}

func (rc *RouterConfig) setupRouteGroups() {
	routeGroups := []RouteGroup{
		rc.getAdminRoutes(),
		rc.getOIDCRoutes(),
		rc.getClientRoutes(),
		rc.getUserRoutes(),
		rc.getConsentRoutes(),
		rc.getAuthorizationRoutes(),
		rc.getTokenRoutes(),
	}

	for _, group := range routeGroups {
		rc.registerRouteGroup(group)
	}
}

func (rc *RouterConfig) registerRouteGroup(group RouteGroup) {
	rc.logger.Info(rc.module, "", "Registering route group: %s", group.Name)
	if len(group.Routes) == 0 {
		rc.logger.Warn(rc.module, "", "No routes found for group: %s", group.Name)
	}

	rc.router.Group(func(r chi.Router) {
		for _, middleware := range group.Middleware {
			r.Use(middleware)
		}

		for _, route := range group.Routes {
			handler := route.Handler
			if len(route.Middleware) > 0 {
				handler = rc.chainMiddleware(route.Handler, route.Middleware...)
			}

			methods := route.getHTTPMethods()
			if len(methods) > 1 {
				r.HandleFunc(route.Pattern, handler)
				rc.logger.Debug(rc.module, "", "Registered routes: [%s] %s", strings.Join(methods, ", "), route.Pattern)
			} else {
				method := methods[0]
				r.Method(method, route.Pattern, handler)
				rc.logger.Debug(rc.module, "", "Registered route: %s %s", method, route.Pattern)
			}
		}
	})
}

func (rc *RouterConfig) chainMiddleware(handler http.HandlerFunc, middleware ...func(http.Handler) http.Handler) http.HandlerFunc {
	for i := len(middleware) - 1; i >= 0; i-- {
		handler = middleware[i](handler).ServeHTTP
	}
	return handler
}
