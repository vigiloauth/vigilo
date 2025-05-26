package container

import (
	"github.com/vigiloauth/vigilo/v2/idp/config"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	cookie "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	crypto "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	email "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	jwt "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	oidc "github.com/vigiloauth/vigilo/v2/internal/domain/oidc"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/middleware"

	auditLogger "github.com/vigiloauth/vigilo/v2/internal/service/audit"
	authzService "github.com/vigiloauth/vigilo/v2/internal/service/authorization"
	authzCodeService "github.com/vigiloauth/vigilo/v2/internal/service/authzcode"
	clientService "github.com/vigiloauth/vigilo/v2/internal/service/client"
	cookieService "github.com/vigiloauth/vigilo/v2/internal/service/cookies"
	cryptoService "github.com/vigiloauth/vigilo/v2/internal/service/crypto"
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
	consentService       LazyInit[consent.UserConsentService]
	loginAttemptService  LazyInit[login.LoginAttemptService]
	authorizationService LazyInit[authz.AuthorizationService]
	httpCookieService    LazyInit[cookie.HTTPCookieService]
	emailService         LazyInit[email.EmailService]
	goMailerService      LazyInit[email.Mailer]
	auditLogger          LazyInit[audit.AuditLogger]
	oidcService          LazyInit[oidc.OIDCService]
	jwtService           LazyInit[jwt.JWTService]
	encryptor            LazyInit[crypto.Cryptographer]
	middlewares          LazyInit[*middleware.Middleware]

	sessionService LazyInit[session.SessionService]
	sessionManager LazyInit[session.SessionManager]

	authzCodeManager          LazyInit[authzCode.AuthorizationCodeManager]
	authzCodeCreator          LazyInit[authzCode.AuthorizationCodeCreator]
	authzCodeIssuer           LazyInit[authzCode.AuthorizationCodeIssuer]
	authzCodeRequestValidator LazyInit[authzCode.AuthorizationCodeValidator]

	clientAuthenticator LazyInit[client.ClientAuthenticator]
	clientValidator     LazyInit[client.ClientValidator]
	clientCreator       LazyInit[client.ClientCreator]
	clientManager       LazyInit[client.ClientManager]
	clientAuthorization LazyInit[client.ClientAuthorization]

	userAuthenticator LazyInit[user.UserAuthenticator]
	userManager       LazyInit[user.UserManager]
	userVerifier      LazyInit[user.UserVerifier]
	userCreator       LazyInit[user.UserCreator]

	tokenManager          LazyInit[token.TokenManager]
	tokenParser           LazyInit[token.TokenParser]
	tokenRequestProcessor LazyInit[token.TokenGrantProcessor]
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
	sr.initMiddleware()

	sr.initTokenRequestProcessor()
	sr.initTokenManager()
	sr.initTokenParser()
	sr.initTokenValidator()
	sr.initTokenCreator()
	sr.initTokenIssuer()
	sr.initJWTService()

	sr.initClientAuthenticator()
	sr.initClientValidator()
	sr.initClientCreator()
	sr.initClientManager()
	sr.initClientAuthorization()

	sr.initUserAuthenticator()
	sr.initUserManager()
	sr.initUserVerifier()
	sr.initUserCreator()

	sr.initAuthzCodeManager()
	sr.initAuthzCodeCreator()
	sr.initAuthzCodeIssuer()
	sr.initAuthzCodeRequestValidator()

	sr.initCryptographer()

	sr.initSessionService()
	sr.initSessionManager()

	sr.initConsentService()
	sr.initLoginAttemptService()
	sr.initAuthorizationService()
	sr.initHTTPCookieService()
	sr.initEmailService()
	sr.initAuditLogger()
	sr.initOIDCService()
}

func (sr *ServiceRegistry) initMiddleware() {
	sr.middlewares = LazyInit[*middleware.Middleware]{
		initFunc: func() *middleware.Middleware {
			return middleware.NewMiddleware(
				sr.TokenParser(),
				sr.TokenValidator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initJWTService() {
	sr.jwtService = LazyInit[jwt.JWTService]{
		initFunc: func() jwt.JWTService {
			return jwtService.NewJWTService()
		},
	}
}

func (sr *ServiceRegistry) initSessionService() {
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

func (sr *ServiceRegistry) initSessionManager() {
	sr.sessionManager = LazyInit[session.SessionManager]{
		initFunc: func() session.SessionManager {
			return sessionService.NewSessionManager(
				sr.db.SessionRepository(),
				sr.HTTPCookieService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initUserAuthenticator() {
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

func (sr *ServiceRegistry) initUserManager() {
	sr.userManager = LazyInit[user.UserManager]{
		initFunc: func() user.UserManager {
			return userService.NewUserManager(
				sr.db.UserRepository(),
				sr.TokenParser(),
				sr.TokenManager(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initUserVerifier() {
	sr.userVerifier = LazyInit[user.UserVerifier]{
		initFunc: func() user.UserVerifier {
			return userService.NewUserVerifier(
				sr.db.UserRepository(),
				sr.TokenParser(),
				sr.TokenValidator(),
				sr.TokenManager(),
			)
		},
	}
}

func (sr *ServiceRegistry) initUserCreator() {
	sr.userCreator = LazyInit[user.UserCreator]{
		initFunc: func() user.UserCreator {
			return userService.NewUserCreator(
				sr.db.UserRepository(),
				sr.TokenIssuer(),
				sr.AuditLogger(),
				sr.EmailService(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initCryptographer() {
	sr.encryptor = LazyInit[crypto.Cryptographer]{
		initFunc: func() crypto.Cryptographer {
			return cryptoService.NewCryptographer()
		},
	}
}

func (sr *ServiceRegistry) initClientAuthenticator() {
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

func (sr *ServiceRegistry) initClientValidator() {
	sr.clientValidator = LazyInit[client.ClientValidator]{
		initFunc: func() client.ClientValidator {
			return clientService.NewClientValidator(
				sr.db.ClientRepository(),
				sr.TokenManager(),
				sr.TokenValidator(),
				sr.TokenParser(),
			)
		},
	}
}

func (sr *ServiceRegistry) initClientCreator() {
	sr.clientCreator = LazyInit[client.ClientCreator]{
		initFunc: func() client.ClientCreator {
			return clientService.NewClientCreator(
				sr.db.ClientRepository(),
				sr.ClientValidator(),
				sr.TokenIssuer(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initClientManager() {
	sr.clientManager = LazyInit[client.ClientManager]{
		initFunc: func() client.ClientManager {
			return clientService.NewClientManager(
				sr.db.ClientRepository(),
				sr.ClientValidator(),
				sr.ClientAuthenticator(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initClientAuthorization() {
	sr.clientAuthorization = LazyInit[client.ClientAuthorization]{
		initFunc: func() client.ClientAuthorization {
			return clientService.NewClientAuthorization(
				sr.ClientValidator(),
				sr.ClientManager(),
				sr.SessionManager(),
				sr.UserConsentService(),
				sr.AuthorizationCodeIssuer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initConsentService() {
	sr.consentService = LazyInit[consent.UserConsentService]{
		initFunc: func() consent.UserConsentService {
			return consentService.NewUserConsentService(
				sr.db.UserConsentRepository(),
				sr.db.UserRepository(),
				sr.SessionService(),
				sr.ClientManager(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthzCodeManager() {
	sr.authzCodeManager = LazyInit[authzCode.AuthorizationCodeManager]{
		initFunc: func() authzCode.AuthorizationCodeManager {
			return authzCodeService.NewAuthorizationCodeManager(
				sr.db.AuthorizationCodeRepository(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthzCodeCreator() {
	sr.authzCodeCreator = LazyInit[authzCode.AuthorizationCodeCreator]{
		initFunc: func() authzCode.AuthorizationCodeCreator {
			return authzCodeService.NewAuthorizationCodeCreator(
				sr.db.AuthorizationCodeRepository(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthzCodeIssuer() {
	sr.authzCodeIssuer = LazyInit[authzCode.AuthorizationCodeIssuer]{
		initFunc: func() authzCode.AuthorizationCodeIssuer {
			return authzCodeService.NewAuthorizationCodeIssuer(
				sr.AuthorizationCodeCreator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initAuthzCodeRequestValidator() {
	sr.authzCodeRequestValidator = LazyInit[authzCode.AuthorizationCodeValidator]{
		initFunc: func() authzCode.AuthorizationCodeValidator {
			return authzCodeService.NewAuthorizationCodeValidator(
				sr.db.AuthorizationCodeRepository(),
				sr.ClientValidator(),
				sr.ClientAuthenticator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initLoginAttemptService() {
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
	sr.authorizationService = LazyInit[authz.AuthorizationService]{
		initFunc: func() authz.AuthorizationService {
			return authzService.NewAuthorizationService(
				sr.AuthorizationCodeManager(),
				sr.UserConsentService(),
				sr.TokenManager(),
				sr.ClientManager(),
				sr.ClientValidator(),
				sr.UserManager(),
				sr.SessionService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initHTTPCookieService() {
	sr.httpCookieService = LazyInit[cookie.HTTPCookieService]{
		initFunc: func() cookie.HTTPCookieService {
			return cookieService.NewHTTPCookieService()
		},
	}
}

func (sr *ServiceRegistry) initEmailService() {
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
	sr.auditLogger = LazyInit[audit.AuditLogger]{
		initFunc: func() audit.AuditLogger {
			return auditLogger.NewAuditLogger(sr.db.AuditEventRepository())
		},
	}
}

func (sr *ServiceRegistry) initOIDCService() {
	sr.oidcService = LazyInit[oidc.OIDCService]{
		initFunc: func() oidc.OIDCService {
			return oidcService.NewOIDCService(sr.AuthorizationService())
		},
	}
}

func (sr *ServiceRegistry) initTokenManager() {
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
	sr.tokenCreator = LazyInit[token.TokenCreator]{
		initFunc: func() token.TokenCreator {
			return tokenService.NewTokenCreator(
				sr.db.TokenRepository(),
				sr.JWTService(),
				sr.Cryptographer(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenParser() {
	sr.tokenParser = LazyInit[token.TokenParser]{
		initFunc: func() token.TokenParser {
			return tokenService.NewTokenParser(
				sr.JWTService(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenIssuer() {
	sr.tokenIssuer = LazyInit[token.TokenIssuer]{
		initFunc: func() token.TokenIssuer {
			return tokenService.NewTokenIssuer(
				sr.TokenCreator(),
			)
		},
	}
}

func (sr *ServiceRegistry) initTokenRequestProcessor() {
	sr.tokenRequestProcessor = LazyInit[token.TokenGrantProcessor]{
		initFunc: func() token.TokenGrantProcessor {
			return tokenService.NewTokenGrantProcessor(
				sr.TokenIssuer(),
				sr.TokenManager(),
				sr.ClientAuthenticator(),
				sr.UserAuthenticator(),
				sr.AuthorizationService(),
			)
		},
	}
}

func (sr *ServiceRegistry) Middleware() *middleware.Middleware {
	return sr.middlewares.Get()
}

func (sr *ServiceRegistry) TokenManager() token.TokenManager {
	return sr.tokenManager.Get()
}

func (sr *ServiceRegistry) TokenParser() token.TokenParser {
	return sr.tokenParser.Get()
}

func (sr *ServiceRegistry) TokenValidator() token.TokenValidator {
	return sr.tokenValidator.Get()
}

func (sr *ServiceRegistry) TokenCreator() token.TokenCreator {
	return sr.tokenCreator.Get()
}

func (sr *ServiceRegistry) TokenGrantProcessor() token.TokenGrantProcessor {
	return sr.tokenRequestProcessor.Get()
}

func (sr *ServiceRegistry) TokenIssuer() token.TokenIssuer {
	return sr.tokenIssuer.Get()
}

func (sr *ServiceRegistry) SessionService() session.SessionService {
	return sr.sessionService.Get()
}

func (sr *ServiceRegistry) SessionManager() session.SessionManager {
	return sr.sessionManager.Get()
}

func (sr *ServiceRegistry) UserAuthenticator() user.UserAuthenticator {
	return sr.userAuthenticator.Get()
}

func (sr *ServiceRegistry) UserManager() user.UserManager {
	return sr.userManager.Get()
}

func (sr *ServiceRegistry) UserVerifier() user.UserVerifier {
	return sr.userVerifier.Get()
}

func (sr *ServiceRegistry) UserCreator() user.UserCreator {
	return sr.userCreator.Get()
}

func (sr *ServiceRegistry) ClientAuthenticator() client.ClientAuthenticator {
	return sr.clientAuthenticator.Get()
}

func (sr *ServiceRegistry) ClientValidator() client.ClientValidator {
	return sr.clientValidator.Get()
}

func (sr *ServiceRegistry) ClientCreator() client.ClientCreator {
	return sr.clientCreator.Get()
}

func (sr *ServiceRegistry) ClientManager() client.ClientManager {
	return sr.clientManager.Get()
}

func (sr *ServiceRegistry) ClientAuthorization() client.ClientAuthorization {
	return sr.clientAuthorization.Get()
}

func (sr *ServiceRegistry) UserConsentService() consent.UserConsentService {
	return sr.consentService.Get()
}

func (sr *ServiceRegistry) AuthorizationCodeManager() authzCode.AuthorizationCodeManager {
	return sr.authzCodeManager.Get()
}

func (sr *ServiceRegistry) AuthorizationCodeCreator() authzCode.AuthorizationCodeCreator {
	return sr.authzCodeCreator.Get()
}

func (sr *ServiceRegistry) AuthorizationCodeIssuer() authzCode.AuthorizationCodeIssuer {
	return sr.authzCodeIssuer.Get()
}

func (sr *ServiceRegistry) AuthorizationCodeRequestValidator() authzCode.AuthorizationCodeValidator {
	return sr.authzCodeRequestValidator.Get()
}

func (sr *ServiceRegistry) LoginAttemptService() login.LoginAttemptService {
	return sr.loginAttemptService.Get()
}

func (sr *ServiceRegistry) AuthorizationService() authz.AuthorizationService {
	return sr.authorizationService.Get()
}

func (sr *ServiceRegistry) HTTPCookieService() cookie.HTTPCookieService {
	return sr.httpCookieService.Get()
}

func (sr *ServiceRegistry) JWTService() jwt.JWTService {
	return sr.jwtService.Get()
}

func (sr *ServiceRegistry) EmailService() email.EmailService {
	return sr.emailService.Get()
}

func (sr *ServiceRegistry) GoMailerService() email.Mailer {
	return sr.goMailerService.Get()
}

func (sr *ServiceRegistry) AuditLogger() audit.AuditLogger {
	return sr.auditLogger.Get()
}

func (sr *ServiceRegistry) OIDCService() oidc.OIDCService {
	return sr.oidcService.Get()
}

func (sr *ServiceRegistry) Cryptographer() crypto.Cryptographer {
	return sr.encryptor.Get()
}
