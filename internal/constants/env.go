package constants

const defaultPath string = "/run/secrets/"

// Environment Variable Names
const (
	CryptoSecretKeyENV string = "CRYPTO_SECRET_KEY"
	SMTPFromAddressENV string = "SMTP_FROM_ADDRESS"
	SMTPPasswordENV    string = "SMTP_PASSWORD"
	SMTPUsernameENV    string = "SMTP_USERNAME"
	TokenIssuerENV     string = "TOKEN_ISSUER"
	TokenPrivateKeyENV string = "TOKEN_PRIVATE_KEY"
	TokenPublicKeyENV  string = "TOKEN_PUBLIC_KEY"

	EnvFilePath     string = "../../.env"
	TestEnvFilePath string = "../../../.env.test"

	SMTPPasswordPath    string = defaultPath + "smtp_password"
	TokenIssuerPath     string = defaultPath + "token_issuer"
	TokenPrivateKeyPath string = defaultPath + "token_private_key"
	TokenPublicKeyPath  string = defaultPath + "token_public_key"
	CryptoSecretKeyPath string = defaultPath + "crypto_secret_key"
)
