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
	jwt "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
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
	jwtService "github.com/vigiloauth/vigilo/v2/internal/service/jwt"
	loginService "github.com/vigiloauth/vigilo/v2/internal/service/login"
	oidcService "github.com/vigiloauth/vigilo/v2/internal/service/oidc"
	sessionService "github.com/vigiloauth/vigilo/v2/internal/service/session"
	tokenService "github.com/vigiloauth/vigilo/v2/internal/service/token"
	userService "github.com/vigiloauth/vigilo/v2/internal/service/user"
	consentService "github.com/vigiloauth/vigilo/v2/internal/service/userconsent"
)

type ServiceRegistry struct {
	db                   *RepositoryRegistry
	sessionService       LazyInit[session.SessionService]
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
	jwtService           LazyInit[jwt.JWTService]

	clientService       LazyInit[client.ClientService]
	clientAuthenticator LazyInit[client.ClientAuthenticator]

	userService       LazyInit[user.UserService]
	userAuthenticator LazyInit[user.UserAuthenticator]

	tokenService          LazyInit[token.TokenService]
	tokenManager          LazyInit[token.TokenManager]
	tokenParser           LazyInit[token.TokenParser]
	tokenRequestProcessor LazyInit[token.TokenRequestProcessor]
	tokenIssuer           LazyInit[token.TokenIssuer]
	tokenValidator        LazyInit[token.TokenValidator]
	tokenCreator          LazyInit[token.TokenCreator]

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
	sr.initTokenRequestProcessor()
	sr.initTokenManager()
	sr.initTokenParser()
	sr.initTokenValidator()
	sr.initTokenCreator()
	sr.initTokenIssuer()

	sr.initJWTService()

	sr.initClientService()
	sr.initClientAuthenticator()

	sr.initUserService()
	sr.initUserAuthenticator()

	sr.initSessionService()
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
			return tokenService.NewTokenService(
				sr.db.TokenRepository(),
				sr.JWTService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initJWTService() {
	sr.logger.Debug(sr.module, "", "Initializing JWT Service")
	sr.jwtService = LazyInit[jwt.JWTService]{
		initFunc: func() jwt.JWTService {
			return jwtService.NewJWTService()
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

func (sr *ServiceRegistry) initUserAuthenticator() {
	sr.logger.Debug(sr.module, "", "Initializing User Authenticator")
	sr.userAuthenticator = LazyInit[user.UserAuthenticator]{
		initFunc: func() user.UserAuthenticator {
			return userService.NewUserAuthenticator(
				sr.db.UserRepository(),
				sr.AuditLogger(),
				sr.LoginAttemptService(),
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

func (sr *ServiceRegistry) initClientAuthenticator() {
	sr.logger.Debug(sr.module, "", "Initializing Client Request Authenticator")
	sr.clientAuthenticator = LazyInit[client.ClientAuthenticator]{
		initFunc: func() client.ClientAuthenticator {
			return clientService.NewClientAuthenticator(
				sr.db.ClientRepository(),
				sr.TokenValidator(),
				sr.TokenParser(),
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

func (sr *ServiceRegistry) initTokenManager() {
	sr.logger.Debug(sr.module, "", "Initializing Token Manager")
	sr.tokenManager = LazyInit[token.TokenManager]{
		initFunc: func() token.TokenManager {
			return tokenService.NewTokenManager(
				sr.db.TokenRepository(),
				sr.TokenParser(),
				sr.TokenValidator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenValidator() {
	sr.logger.Debug(sr.module, "", "Initializing Token Validator")
	sr.tokenValidator = LazyInit[token.TokenValidator]{
		initFunc: func() token.TokenValidator {
			return tokenService.NewTokenValidator(
				sr.db.TokenRepository(),
				sr.TokenParser(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenCreator() {
	sr.logger.Debug(sr.module, "", "Initializing Token Creator")
	sr.tokenCreator = LazyInit[token.TokenCreator]{
		initFunc: func() token.TokenCreator {
			return tokenService.NewTokenCreator(
				sr.db.TokenRepository(),
				sr.JWTService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenParser() {
	sr.logger.Debug(sr.module, "", "Initializing Token Parser")
	sr.tokenParser = LazyInit[token.TokenParser]{
		initFunc: func() token.TokenParser {
			return tokenService.NewTokenParser(
				sr.JWTService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenIssuer() {
	sr.logger.Debug(sr.module, "", "Initializing Token Issuer")
	sr.tokenIssuer = LazyInit[token.TokenIssuer]{
		initFunc: func() token.TokenIssuer {
			return tokenService.NewTokenIssuer(
				sr.TokenCreator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenRequestProcessor() {
	sr.logger.Debug(sr.module, "", "Initializing Token Issuer")
	sr.tokenRequestProcessor = LazyInit[token.TokenRequestProcessor]{
		initFunc: func() token.TokenRequestProcessor {
			return tokenService.NewTokenRequestProcessor(
				sr.TokenIssuer(),
				sr.ClientAuthenticator(),
				sr.UserAuthenticator(),
			)
		},
	}
}

func (sr *ServiceRegistry) TokenService() token.TokenService {
	sr.logger.Debug(sr.module, "", "Getting Token Service")
	return sr.tokenService.Get()
}

func (sr *ServiceRegistry) TokenManager() token.TokenManager {
	sr.logger.Debug(sr.module, "", "Getting Token Management Service")
	return sr.tokenManager.Get()
}

func (sr *ServiceRegistry) TokenParser() token.TokenParser {
	sr.logger.Debug(sr.module, "", "Getting Token Parser")
	return sr.tokenParser.Get()
}

func (sr *ServiceRegistry) TokenValidator() token.TokenValidator {
	sr.logger.Debug(sr.module, "", "Getting Token Validator")
	return sr.tokenValidator.Get()
}

func (sr *ServiceRegistry) TokenCreator() token.TokenCreator {
	sr.logger.Debug(sr.module, "", "Getting Token Creator")
	return sr.tokenCreator.Get()
}

func (sr *ServiceRegistry) TokenRequestProcessor() token.TokenRequestProcessor {
	sr.logger.Debug(sr.module, "", "Getting Token Request Processor")
	return sr.tokenRequestProcessor.Get()
}

func (sr *ServiceRegistry) TokenIssuer() token.TokenIssuer {
	sr.logger.Debug(sr.module, "", "Getting Token Issuer")
	return sr.tokenIssuer.Get()
}

func (sr *ServiceRegistry) SessionService() session.SessionService {
	sr.logger.Debug(sr.module, "", "Getting Session Service")
	return sr.sessionService.Get()
}

func (sr *ServiceRegistry) UserService() user.UserService {
	sr.logger.Debug(sr.module, "", "Getting User Service")
	return sr.userService.Get()
}

func (sr *ServiceRegistry) UserAuthenticator() user.UserAuthenticator {
	sr.logger.Debug(sr.module, "", "Getting User Authenticator")
	return sr.userAuthenticator.Get()
}

func (sr *ServiceRegistry) ClientService() client.ClientService {
	sr.logger.Debug(sr.module, "", "Getting Client Service")
	return sr.clientService.Get()
}

func (sr *ServiceRegistry) ClientAuthenticator() client.ClientAuthenticator {
	sr.logger.Debug(sr.module, "", "Getting Client Request Authenticator")
	return sr.clientAuthenticator.Get()
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

func (sr *ServiceRegistry) JWTService() jwt.JWTService {
	sr.logger.Debug(sr.module, "", "Getting JWT Service")
	return sr.jwtService.Get()
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
