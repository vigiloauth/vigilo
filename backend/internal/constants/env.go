package constants

// Environment Variable Names
const (
	CryptoSecretKeyENV  string = "CRYPTO_SECRET_KEY"
	SMTPFromAddressENV  string = "SMTP_FROM_ADDRESS"
	SMTPPasswordENV     string = "SMTP_PASSWORD"
	SMTPUsernameENV     string = "SMTP_USERNAME"
	TokenIssuerENV      string = "TOKEN_ISSUER"
	TokenPrivateKeyENV  string = "TOKEN_PRIVATE_KEY"
	TokenPublicKeyENV   string = "TOKEN_PUBLIC_KEY"
	ReactBuildPathENV   string = "REACT_BUILD_PATH"
	VigiloServerModeENV string = "VIGILO_SERVER_MODE"

	EnvFilePath     string = "../../.env"
	TestEnvFilePath string = "../../../.env.test"
)
