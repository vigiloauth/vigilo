package container

import (
	"github.com/vigiloauth/vigilo/v2/idp/config"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	userConsent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"

	auditEventRepo "github.com/vigiloauth/vigilo/v2/internal/repository/audit"
	authzCodeRepo "github.com/vigiloauth/vigilo/v2/internal/repository/authzcode"
	clientRepo "github.com/vigiloauth/vigilo/v2/internal/repository/client"
	loginRepo "github.com/vigiloauth/vigilo/v2/internal/repository/login"
	sessionRepo "github.com/vigiloauth/vigilo/v2/internal/repository/session"
	tokenRepo "github.com/vigiloauth/vigilo/v2/internal/repository/token"
	userRepo "github.com/vigiloauth/vigilo/v2/internal/repository/user"
	consentRepo "github.com/vigiloauth/vigilo/v2/internal/repository/userconsent"
)

type RepositoryRegistry struct {
	tokenRepo        token.TokenRepository
	loginAttemptRepo login.LoginAttemptRepository
	userRepo         user.UserRepository
	clientRepo       domain.ClientRepository
	consentRepo      userConsent.UserConsentRepository
	authzCodeRepo    authzCode.AuthorizationCodeRepository
	sessionRepo      session.SessionRepository
	auditEventRepo   audit.AuditRepository

	logger *config.Logger
	module string
}

func NewRepositoryRegistry(logger *config.Logger) *RepositoryRegistry {
	module := "Repository Registry"
	logger.Info(module, "", "Initializing repositories")

	rr := &RepositoryRegistry{
		logger: logger,
		module: module,
	}

	rr.initInMemoryRepositories()
	return rr
}

func (dr *RepositoryRegistry) initInMemoryRepositories() {
	dr.tokenRepo = tokenRepo.GetInMemoryTokenRepository()
	dr.loginAttemptRepo = loginRepo.GetInMemoryLoginRepository()
	dr.userRepo = userRepo.GetInMemoryUserRepository()
	dr.clientRepo = clientRepo.GetInMemoryClientRepository()
	dr.consentRepo = consentRepo.GetInMemoryUserConsentRepository()
	dr.authzCodeRepo = authzCodeRepo.GetInMemoryAuthorizationCodeRepository()
	dr.sessionRepo = sessionRepo.GetInMemorySessionRepository()
	dr.auditEventRepo = auditEventRepo.GetInMemoryAuditEventRepository()
}

func (dr *RepositoryRegistry) TokenRepository() token.TokenRepository {
	return dr.tokenRepo
}

func (dr *RepositoryRegistry) LoginAttemptRepository() login.LoginAttemptRepository {
	return dr.loginAttemptRepo
}

func (dr *RepositoryRegistry) UserRepository() user.UserRepository {
	return dr.userRepo
}

func (dr *RepositoryRegistry) ClientRepository() domain.ClientRepository {
	return dr.clientRepo
}

func (dr *RepositoryRegistry) UserConsentRepository() userConsent.UserConsentRepository {
	return dr.consentRepo
}

func (dr *RepositoryRegistry) AuthorizationCodeRepository() authzCode.AuthorizationCodeRepository {
	return dr.authzCodeRepo
}

func (dr *RepositoryRegistry) SessionRepository() session.SessionRepository {
	return dr.sessionRepo
}

func (dr *RepositoryRegistry) AuditEventRepository() audit.AuditRepository {
	return dr.auditEventRepo
}
