package container

import (
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/handlers"
)

type HandlerRegistry struct {
	sr            *ServiceRegistry
	userHandler   LazyInit[*handlers.UserHandler]
	clientHandler LazyInit[*handlers.ClientHandler]
	tokenHandler  LazyInit[*handlers.TokenHandler]
	authzHandler  LazyInit[*handlers.AuthorizationHandler]
	oauthHandler  LazyInit[*handlers.OAuthHandler]
	adminHandler  LazyInit[*handlers.AdminHandler]
	oidcHandler   LazyInit[*handlers.OIDCHandler]

	logger *config.Logger
	module string
}

func NewHandlerRegistry(sr *ServiceRegistry, logger *config.Logger) *HandlerRegistry {
	module := "Handler Registry"
	logger.Info(module, "", "Initializing handlers")

	h := &HandlerRegistry{
		sr:     sr,
		logger: logger,
		module: module,
	}

	h.initHandlers()
	return h
}

func (h *HandlerRegistry) initHandlers() {
	h.initUserHandler()
	h.initClientHandler()
	h.initTokenHandler()
	h.initAuthzHandler()
	h.initOAuthHandler()
	h.initAdminHandler()
	h.initOIDCHandler()
}

func (h *HandlerRegistry) initUserHandler() {
	h.logger.Debug(h.module, "", "Initializing User Handler")
	h.userHandler = LazyInit[*handlers.UserHandler]{
		initFunc: func() *handlers.UserHandler {
			return handlers.NewUserHandler(
				h.sr.UserService(),
				h.sr.SessionService(),
			)
		},
	}
}

func (h *HandlerRegistry) initClientHandler() {
	h.logger.Debug(h.module, "", "Initializing Client Handler")
	h.clientHandler = LazyInit[*handlers.ClientHandler]{
		initFunc: func() *handlers.ClientHandler {
			return handlers.NewClientHandler(h.sr.ClientService())
		},
	}
}

func (h *HandlerRegistry) initTokenHandler() {
	h.logger.Debug(h.module, "", "Initializing Token Handler")
	h.tokenHandler = LazyInit[*handlers.TokenHandler]{
		initFunc: func() *handlers.TokenHandler {
			return handlers.NewTokenHandler(
				h.sr.AuthenticationService(),
				h.sr.SessionService(),
				h.sr.AuthorizationService(),
			)
		},
	}
}

func (h *HandlerRegistry) initAuthzHandler() {
	h.logger.Debug(h.module, "", "Initializing Authorization Handler")
	h.authzHandler = LazyInit[*handlers.AuthorizationHandler]{
		initFunc: func() *handlers.AuthorizationHandler {
			return handlers.NewAuthorizationHandler(
				h.sr.AuthorizationService(),
				h.sr.SessionService(),
			)
		},
	}
}

func (h *HandlerRegistry) initOAuthHandler() {
	h.logger.Debug(h.module, "", "Initializing OAuth Handler")
	h.oauthHandler = LazyInit[*handlers.OAuthHandler]{
		initFunc: func() *handlers.OAuthHandler {
			return handlers.NewOAuthHandler(
				h.sr.UserService(),
				h.sr.SessionService(),
				h.sr.ClientService(),
				h.sr.UserConsentService(),
				h.sr.AuthorizationCodeService(),
			)
		},
	}
}

func (h *HandlerRegistry) initAdminHandler() {
	h.logger.Debug(h.module, "", "Initializing Admin Handler")
	h.adminHandler = LazyInit[*handlers.AdminHandler]{
		initFunc: func() *handlers.AdminHandler {
			return handlers.NewAdminHandler(h.sr.AuditLogger())
		},
	}
}

func (h *HandlerRegistry) initOIDCHandler() {
	h.logger.Debug(h.module, "", "Initializing OIDC Handler")
	h.oidcHandler = LazyInit[*handlers.OIDCHandler]{
		initFunc: func() *handlers.OIDCHandler {
			return handlers.NewOIDCHandler(h.sr.OIDCService())
		},
	}
}

func (h *HandlerRegistry) UserHandler() *handlers.UserHandler {
	h.logger.Debug(h.module, "", "Getting User Handler")
	return h.userHandler.Get()
}

func (h *HandlerRegistry) GetClientHandler() *handlers.ClientHandler {
	h.logger.Debug(h.module, "", "Getting Client Handler")
	return h.clientHandler.Get()
}

func (h *HandlerRegistry) TokenHandler() *handlers.TokenHandler {
	h.logger.Debug(h.module, "", "Getting Token Handler")
	return h.tokenHandler.Get()
}

func (h *HandlerRegistry) AuthorizationHandler() *handlers.AuthorizationHandler {
	h.logger.Debug(h.module, "", "Getting Authorization Handler")
	return h.authzHandler.Get()
}

func (h *HandlerRegistry) OAuthHandler() *handlers.OAuthHandler {
	h.logger.Debug(h.module, "", "Getting OAuth Handler")
	return h.oauthHandler.Get()
}

func (h *HandlerRegistry) AdminHandler() *handlers.AdminHandler {
	h.logger.Debug(h.module, "", "Getting Admin Handler")
	return h.adminHandler.Get()
}

func (h *HandlerRegistry) GetOIDCHandler() *handlers.OIDCHandler {
	h.logger.Debug(h.module, "", "Getting OIDC Handler")
	return h.oidcHandler.Get()
}
