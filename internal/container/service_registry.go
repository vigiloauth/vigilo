package container

import (
	"github.com/vigiloauth/vigilo/v2/idp/config"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	auth "github.com/vigiloauth/vigilo/v2/internal/domain/authentication"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	cookie "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	email "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	oidc "github.com/vigiloauth/vigilo/v2/internal/domain/oidc"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"

	auditLogger "github.com/vigiloauth/vigilo/v2/internal/service/audit"
	authService "github.com/vigiloauth/vigilo/v2/internal/service/authentication"
	authzService "github.com/vigiloauth/vigilo/v2/internal/service/authorization"
	authzCodeService "github.com/vigiloauth/vigilo/v2/internal/service/authzcode"
	clientService "github.com/vigiloauth/vigilo/v2/internal/service/client"
	cookieService "github.com/vigiloauth/vigilo/v2/internal/service/cookies"
	emailService "github.com/vigiloauth/vigilo/v2/internal/service/email"
	loginService "github.com/vigiloauth/vigilo/v2/internal/service/login"
	oidcService "github.com/vigiloauth/vigilo/v2/internal/service/oidc"
	sessionService "github.com/vigiloauth/vigilo/v2/internal/service/session"
	tokenService "github.com/vigiloauth/vigilo/v2/internal/service/token"
	userService "github.com/vigiloauth/vigilo/v2/internal/service/user"
	consentService "github.com/vigiloauth/vigilo/v2/internal/service/userconsent"
)

type ServiceRegistry struct {
	db                   *RepositoryRegistry
	tokenService         LazyInit[token.TokenService]
	sessionService       LazyInit[session.SessionService]
	userService          LazyInit[user.UserService]
	clientService        LazyInit[client.ClientService]
	consentService       LazyInit[consent.UserConsentService]
	authzCodeService     LazyInit[authzCode.AuthorizationCodeService]
	loginAttemptService  LazyInit[login.LoginAttemptService]
	authorizationService LazyInit[authz.AuthorizationService]
	httpCookieService    LazyInit[cookie.HTTPCookieService]
	authService          LazyInit[auth.AuthenticationService]
	emailService         LazyInit[email.EmailService]
	goMailerService      LazyInit[email.Mailer]
	auditLogger          LazyInit[audit.AuditLogger]
	oidcService          LazyInit[oidc.OIDCService]

	logger *config.Logger
	module string
}

func NewServiceRegistry(dbRegistry *RepositoryRegistry, logger *config.Logger) *ServiceRegistry {
	module := "Service Registry"
	logger.Info(module, "", "Initializing services")

	sr := &ServiceRegistry{
		logger: logger,
		module: module,
		db:     dbRegistry,
	}

	sr.initServices()

	return sr
}

func (sr *ServiceRegistry) initServices() {
	sr.initTokenService()
	sr.initSessionService()
	sr.initUserService()
	sr.initClientService()
	sr.initConsentService()
	sr.initAuthzCodeService()
	sr.initLoginAttemptService()
	sr.initAuthorizationService()
	sr.initHTTPCookieService()
	sr.initAuthenticationService()
	sr.initEmailService()
	sr.initAuditLogger()
	sr.initOIDCService()
}

func (sr *ServiceRegistry) initTokenService() {
	sr.logger.Debug(sr.module, "", "Initializing Token Service")
	sr.tokenService = LazyInit[token.TokenService]{
		initFunc: func() token.TokenService {
			return tokenService.NewTokenService(sr.db.TokenRepository())
		},
	}
}

func (sr *ServiceRegistry) initSessionService() {
	sr.logger.Debug(sr.module, "", "Initializing Session Service")
	sr.sessionService = LazyInit[session.SessionService]{
		initFunc: func() session.SessionService {
			return sessionService.NewSessionService(
				sr.db.SessionRepository(),
				sr.HTTPCookieService(),
				sr.AuditLogger(),
			)
		},
	}
}

func (sr *ServiceRegistry) initUserService() {
	sr.logger.Debug(sr.module, "", "Initializing User Service")
	sr.userService = LazyInit[user.UserService]{
		initFunc: func() user.UserService {
			return userService.NewUserService(
				sr.db.UserRepository(),
				sr.TokenService(),
				sr.LoginAttemptService(),
				sr.EmailService(),
				sr.AuditLogger(),
			)
		},
	}
}

func (sr *ServiceRegistry) initClientService() {
	sr.logger.Debug(sr.module, "", "Initializing Client Service")
	sr.clientService = LazyInit[client.ClientService]{
		initFunc: func() client.ClientService {
			return clientService.NewClientService(
				sr.db.ClientRepository(),
				sr.TokenService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initConsentService() {
	sr.logger.Debug(sr.module, "", "Initializing User Consent Service")
	sr.consentService = LazyInit[consent.UserConsentService]{
		initFunc: func() consent.UserConsentService {
			return consentService.NewUserConsentService(
				sr.db.UserConsentRepository(),
				sr.db.UserRepository(),
				sr.SessionService(),
				sr.ClientService(),
				sr.AuthorizationCodeService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthzCodeService() {
	sr.logger.Debug(sr.module, "", "Initializing Authorization Code Service")
	sr.authzCodeService = LazyInit[authzCode.AuthorizationCodeService]{
		initFunc: func() authzCode.AuthorizationCodeService {
			return authzCodeService.NewAuthorizationCodeService(
				sr.db.AuthorizationCodeRepository(),
				sr.UserService(),
				sr.ClientService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initLoginAttemptService() {
	sr.logger.Debug(sr.module, "", "Initializing Login Attempt Service")
	sr.loginAttemptService = LazyInit[login.LoginAttemptService]{
		initFunc: func() login.LoginAttemptService {
			return loginService.NewLoginAttemptService(
				sr.db.UserRepository(),
				sr.db.LoginAttemptRepository(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthorizationService() {
	sr.logger.Debug(sr.module, "", "Initializing Authorization Service")
	sr.authorizationService = LazyInit[authz.AuthorizationService]{
		initFunc: func() authz.AuthorizationService {
			return authzService.NewAuthorizationService(
				sr.AuthorizationCodeService(),
				sr.UserConsentService(),
				sr.TokenService(),
				sr.ClientService(),
				sr.UserService(),
				sr.SessionService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initHTTPCookieService() {
	sr.logger.Debug(sr.module, "", "Initializing HTTP Cookie Service")
	sr.httpCookieService = LazyInit[cookie.HTTPCookieService]{
		initFunc: func() cookie.HTTPCookieService {
			return cookieService.NewHTTPCookieService()
		},
	}
}

func (sr *ServiceRegistry) initAuthenticationService() {
	sr.logger.Debug(sr.module, "", "Initializing Authentication Service")
	sr.authService = LazyInit[auth.AuthenticationService]{
		initFunc: func() auth.AuthenticationService {
			return authService.NewAuthenticationService(
				sr.TokenService(),
				sr.ClientService(),
				sr.UserService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initEmailService() {
	sr.logger.Debug(sr.module, "", "Initializing Email Service")
	sr.emailService = LazyInit[email.EmailService]{
		initFunc: func() email.EmailService {
			return emailService.NewEmailService(sr.GoMailerService())
		},
	}
	sr.goMailerService = LazyInit[email.Mailer]{
		initFunc: func() email.Mailer {
			return emailService.NewGoMailer()
		},
	}
}

func (sr *ServiceRegistry) initAuditLogger() {
	sr.logger.Debug(sr.module, "", "Initializing Audit Logger")
	sr.auditLogger = LazyInit[audit.AuditLogger]{
		initFunc: func() audit.AuditLogger {
			return auditLogger.NewAuditLogger(sr.db.AuditEventRepository())
		},
	}
}

func (sr *ServiceRegistry) initOIDCService() {
	sr.logger.Debug(sr.module, "", "Initializing OIDC Service")
	sr.oidcService = LazyInit[oidc.OIDCService]{
		initFunc: func() oidc.OIDCService {
			return oidcService.NewOIDCService(sr.AuthorizationService())
		},
	}
}

func (sr *ServiceRegistry) TokenService() token.TokenService {
	sr.logger.Debug(sr.module, "", "Getting Token Service")
	return sr.tokenService.Get()
}

func (sr *ServiceRegistry) SessionService() session.SessionService {
	sr.logger.Debug(sr.module, "", "Getting Session Service")
	return sr.sessionService.Get()
}

func (sr *ServiceRegistry) UserService() user.UserService {
	sr.logger.Debug(sr.module, "", "Getting User Service")
	return sr.userService.Get()
}

func (sr *ServiceRegistry) ClientService() client.ClientService {
	sr.logger.Debug(sr.module, "", "Getting Client Service")
	return sr.clientService.Get()
}

func (sr *ServiceRegistry) UserConsentService() consent.UserConsentService {
	sr.logger.Debug(sr.module, "", "Getting User Consent Service")
	return sr.consentService.Get()
}

func (sr *ServiceRegistry) AuthorizationCodeService() authzCode.AuthorizationCodeService {
	sr.logger.Debug(sr.module, "", "Getting Authorization Code Service")
	return sr.authzCodeService.Get()
}

func (sr *ServiceRegistry) LoginAttemptService() login.LoginAttemptService {
	sr.logger.Debug(sr.module, "", "Getting Login Attempt Service")
	return sr.loginAttemptService.Get()
}

func (sr *ServiceRegistry) AuthorizationService() authz.AuthorizationService {
	sr.logger.Debug(sr.module, "", "Getting Authorization Service")
	return sr.authorizationService.Get()
}

func (sr *ServiceRegistry) HTTPCookieService() cookie.HTTPCookieService {
	sr.logger.Debug(sr.module, "", "Getting HTTP Cookie Service")
	return sr.httpCookieService.Get()
}

func (sr *ServiceRegistry) AuthenticationService() auth.AuthenticationService {
	sr.logger.Debug(sr.module, "", "Getting Authentication Service")
	return sr.authService.Get()
}

func (sr *ServiceRegistry) EmailService() email.EmailService {
	sr.logger.Debug(sr.module, "", "Getting Email Service")
	return sr.emailService.Get()
}

func (sr *ServiceRegistry) GoMailerService() email.Mailer {
	sr.logger.Debug(sr.module, "", "Getting Go Mailer Service")
	return sr.goMailerService.Get()
}

func (sr *ServiceRegistry) AuditLogger() audit.AuditLogger {
	sr.logger.Debug(sr.module, "", "Getting Audit Logger")
	return sr.auditLogger.Get()
}

func (sr *ServiceRegistry) OIDCService() oidc.OIDCService {
	sr.logger.Debug(sr.module, "", "Getting OIDC Service")
	return sr.oidcService.Get()
}
