package domain

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type Jwks struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`           // Key type (e.g., "RSA", "EC")
	Kid string `json:"kid"`           // Key ID, used to identify the key
	Use string `json:"use"`           // Public key use (e.g., "sig" for signature, "enc" for encryption)
	Alg string `json:"alg"`           // Algorithm intended for use with the key (e.g., "RS256", "ES256")
	N   string `json:"n,omitempty"`   // RSA modulus (base64url-encoded)
	E   string `json:"e,omitempty"`   // RSA public exponent (base64url-encoded)
	X   string `json:"x,omitempty"`   // EC public key x-coordinate (base64url-encoded)
	Y   string `json:"y,omitempty"`   // EC public key y-coordinate (base64url-encoded)
	Crv string `json:"crv,omitempty"` // EC curve name (e.g., "P-256", "P-384", "P-521")
}

func NewJWK(keyID string, publicKey *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Kid: keyID,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}
