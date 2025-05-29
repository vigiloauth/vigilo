package constants

// OIDC Constants define values used in OpenID Connect (OIDC) for token signing,
// encryption, subject types, and client authentication methods.
const (
	SubjectTypePublic             string = "public" // Public subject type for OIDC (e.g., non-pairwise identifiers)
	SubjectTypePairwise           string = "pairwise"
	IDTokenSigningAlgorithmRS256  string = "RS256"               // Signing algorithm for ID tokens (RSA with SHA-256)
	IDTokenEncryptionAlgorithmRSA string = "RSA-OAEP"            // Encryption algorithm for ID tokens (RSA-OAEP)
	AuthMethodClientSecretPost    string = "client_secret_post"  // Client authentication using client_id and client_secret in the request body
	AuthMethodClientSecretBasic   string = "client_secret_basic" // Client authentication using client_id and client_secret in the Authorization header
	AuthMethodNone                string = "none"                // No client authentication (used for public clients, e.g., with PKCE)
)
