package config

import (
	"os"

	audit "github.com/vigiloauth/vigilo/v2/cmd/config/audit"
	login "github.com/vigiloauth/vigilo/v2/cmd/config/login"
	password "github.com/vigiloauth/vigilo/v2/cmd/config/password"
	server "github.com/vigiloauth/vigilo/v2/cmd/config/server"
	smtp "github.com/vigiloauth/vigilo/v2/cmd/config/smtp"
	token "github.com/vigiloauth/vigilo/v2/cmd/config/token"

	lib "github.com/vigiloauth/vigilo/v2/idp/config"
	"gopkg.in/yaml.v3"
)

type ApplicationConfig struct {
	ServerConfig   server.ServerConfigYAML     `yaml:"server_config"`
	TokenConfig    token.TokenConfigYAML       `yaml:"token_config,omitempty"`
	PasswordConfig password.PasswordConfigYAML `yaml:"password_config,omitempty"`
	LoginConfig    login.LoginConfigYAML       `yaml:"login_config,omitempty"`
	SMTPConfig     smtp.SMTPConfigYAML         `yaml:"smtp_config,omitempty"`
	AuditLogConfig audit.AuditLogConfigYAML    `yaml:"audit_config,omitempty"`

	LogLevel *string `yaml:"log_level,omitempty"`
	Logger   *lib.Logger
	Module   string
}

func LoadConfigurations() *ApplicationConfig {
	configFile := os.Getenv("VIGILO_CONFIG_PATH")
	ac := &ApplicationConfig{
		Logger: lib.GetLogger(),
		Module: "Identity Server",
	}

	appConfig := ac.loadFromYAML(configFile)
	loginOptions := appConfig.LoginConfig.ToOptions()
	loginConfig := lib.NewLoginConfig(loginOptions...)

	passwordOptions := appConfig.PasswordConfig.ToOptions()
	passwordConfig := lib.NewPasswordConfig(passwordOptions...)

	tokenOptions := appConfig.TokenConfig.ToOptions()
	tokenConfig := lib.NewTokenConfig(tokenOptions...)

	smtpOptions := appConfig.SMTPConfig.ToOptions()
	smtpConfig := lib.NewSMTPConfig(smtpOptions...)

	auditLogOptions := appConfig.AuditLogConfig.ToOptions()
	auditLogConfig := lib.NewAuditLogConfig(auditLogOptions...)

	serverOptions := appConfig.ServerConfig.ToOptions()
	serverConfig := lib.NewServerConfig(serverOptions...)
	serverConfig.SetLoginConfig(loginConfig)
	serverConfig.SetPasswordConfig(passwordConfig)
	serverConfig.SetTokenConfig(tokenConfig)
	serverConfig.SetSMTPConfig(smtpConfig)
	serverConfig.SetAuditLogConfig(auditLogConfig)

	if appConfig.LogLevel != nil {
		lib.SetLevel(*appConfig.LogLevel)
	}

	return appConfig
}

func (ac *ApplicationConfig) loadFromYAML(path string) *ApplicationConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		ac.Logger.Fatal(ac.Module, "", "Failed to load yaml configuration: %v", err)
	}

	var appConfig ApplicationConfig
	if err := yaml.Unmarshal(data, &appConfig); err != nil {
		ac.Logger.Fatal(ac.Module, "", "Failed to unmarshal YAML: %v", err)
	}

	return &appConfig
}
