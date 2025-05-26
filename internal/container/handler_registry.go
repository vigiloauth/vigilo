package container

import (
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/handlers"
)

type HandlerRegistry struct {
	sr            *ServiceRegistry
	userHandler   LazyInit[*handlers.UserHandler]
	clientHandler LazyInit[*handlers.ClientHandler]
	tokenHandler  LazyInit[*handlers.TokenHandler]
	authzHandler  LazyInit[*handlers.AuthorizationHandler]
	oauthHandler  LazyInit[*handlers.ConsentHandler]
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
	h.userHandler = LazyInit[*handlers.UserHandler]{
		initFunc: func() *handlers.UserHandler {
			return handlers.NewUserHandler(
				h.sr.UserCreator(),
				h.sr.UserAuthenticator(),
				h.sr.UserManager(),
				h.sr.UserVerifier(),
				h.sr.SessionService(),
			)
		},
	}
}

func (h *HandlerRegistry) initClientHandler() {
	h.clientHandler = LazyInit[*handlers.ClientHandler]{
		initFunc: func() *handlers.ClientHandler {
			return handlers.NewClientHandler(
				h.sr.ClientCreator(),
				h.sr.ClientManager(),
			)
		},
	}
}

func (h *HandlerRegistry) initTokenHandler() {
	h.tokenHandler = LazyInit[*handlers.TokenHandler]{
		initFunc: func() *handlers.TokenHandler {
			return handlers.NewTokenHandler(
				h.sr.TokenGrantProcessor(),
			)
		},
	}
}

func (h *HandlerRegistry) initAuthzHandler() {
	h.authzHandler = LazyInit[*handlers.AuthorizationHandler]{
		initFunc: func() *handlers.AuthorizationHandler {
			return handlers.NewAuthorizationHandler(
				h.sr.ClientAuthorization(),
			)
		},
	}
}

func (h *HandlerRegistry) initOAuthHandler() {
	h.oauthHandler = LazyInit[*handlers.ConsentHandler]{
		initFunc: func() *handlers.ConsentHandler {
			return handlers.NewConsentHandler(
				h.sr.SessionService(),
				h.sr.UserConsentService(),
			)
		},
	}
}

func (h *HandlerRegistry) initAdminHandler() {
	h.adminHandler = LazyInit[*handlers.AdminHandler]{
		initFunc: func() *handlers.AdminHandler {
			return handlers.NewAdminHandler(h.sr.AuditLogger())
		},
	}
}

func (h *HandlerRegistry) initOIDCHandler() {
	h.oidcHandler = LazyInit[*handlers.OIDCHandler]{
		initFunc: func() *handlers.OIDCHandler {
			return handlers.NewOIDCHandler(h.sr.OIDCService())
		},
	}
}

func (h *HandlerRegistry) UserHandler() *handlers.UserHandler {
	return h.userHandler.Get()
}

func (h *HandlerRegistry) ClientHandler() *handlers.ClientHandler {
	return h.clientHandler.Get()
}

func (h *HandlerRegistry) TokenHandler() *handlers.TokenHandler {
	return h.tokenHandler.Get()
}

func (h *HandlerRegistry) AuthorizationHandler() *handlers.AuthorizationHandler {
	return h.authzHandler.Get()
}

func (h *HandlerRegistry) OAuthHandler() *handlers.ConsentHandler {
	return h.oauthHandler.Get()
}

func (h *HandlerRegistry) AdminHandler() *handlers.AdminHandler {
	return h.adminHandler.Get()
}

func (h *HandlerRegistry) OIDCHandler() *handlers.OIDCHandler {
	return h.oidcHandler.Get()
}
