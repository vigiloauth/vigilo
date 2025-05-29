package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"golang.org/x/crypto/bcrypt"
)

var _ domain.Cryptographer = (*cryptographer)(nil)

const (
	keyLength   int = 32
	nonceLength int = 12
)

type cryptographer struct {
	logger *config.Logger
	module string
}

// NewCryptographer creates a new instance of Cryptographer.
func NewCryptographer() domain.Cryptographer {
	return &cryptographer{
		logger: config.GetServerConfig().Logger(),
		module: "Cryptographer",
	}
}

// EncryptString encrypts a plaintext string using AES-GCM and a secret key.
// It returns the base64-encoded encrypted string.
//
// Parameters:
//   - plainStr string: The plaintext string to encrypt.
//   - secretKey string: A 32-byte key for AES-256 encryption (make sure to store this securely).
//
// Returns:
//   - string: The encrypted text, base64-encoded.
//   - error: Error if an encryption issue occurs.
func (c *cryptographer) EncryptString(plainStr, secretKey string) (string, error) {
	key, err := c.decodeAndValidateSecretKey(secretKey)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptString]: Failed to decode or validate secret key: %v", err)
		return "", errors.Wrap(err, "", "failed to decode or validate secret key")
	}

	block, err := c.generateAESCipherBlock(key)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptString]: Failed to create AES cipher block: %v", err)
		return "", errors.Wrap(err, "", "failed to create AES cipher block")
	}

	nonce, err := c.generateRandomNonce()
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptString]: Failed to generate random nonce: %v", err)

		return "", errors.Wrap(err, "", "failed to generate random nonce")
	}

	aesGCM, err := c.generateGCMCipher(block)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptString]: Failed to create GCM cipher: %v", err)
		return "", errors.Wrap(err, "", "failed to create GCM cipher")
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(plainStr), nil)
	result := append(nonce, cipherText...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptString decrypts a base64-encoded cipher text string using AES-GCM and a secret key.
// It returns the decrypted plaintext string.
//
// Parameters:
//   - encryptedStr string: The base64-encoded encrypted string.
//   - secretKey: string The secret key used for encryption.
//
// Returns:
//   - string: The decrypted plaintext string.
//   - error: Error if decryption fails.
func (c *cryptographer) DecryptString(encryptedStr, secretKey string) (string, error) {
	key, err := c.decodeAndValidateSecretKey(secretKey)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptString]: Failed to decode or validate secret key: %v", err)
		return "", errors.Wrap(err, "", "failed to decode or validate secret key")
	}

	cipherText, err := c.decodeBase64String(encryptedStr)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptString]: Failed to decode base64 string: %v", err)
		return "", errors.Wrap(err, "", "failed to decode base64 string")
	}

	nonce := cipherText[:12]
	block, err := c.generateAESCipherBlock(key)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptString]: Failed to create AES cipher block: %v", err)
		return "", errors.Wrap(err, "", "failed to create AES cipher block")
	}

	aesGCM, err := c.generateGCMCipher(block)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptString]: Failed to create GCM cipher: %v", err)
		return "", errors.Wrap(err, "", "failed to create GCM cipher")
	}

	plaintext, err := c.decryptCipherText(aesGCM, nonce, cipherText[12:])
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptString]: Failed to decrypt cipher text: %v", err)
		return "", errors.Wrap(err, "", "failed to decrypt cipher text")
	}

	return string(plaintext), nil
}

// EncryptBytes encrypts a given byte slice using AES-GCM mode.
//
// Parameters:
//   - plainBytes []byte: The byte slice to encrypt.
//   - secretKey []byte: The key used for encryption. It must be 32 bytes long for AES-256.
//
// Returns:
//   - string: The base64-encoded encrypted data.
//   - error: Any error that occurs during encryption.
func (c *cryptographer) EncryptBytes(plainBytes []byte, secretKey string) (string, error) {
	key, err := c.decodeAndValidateSecretKey(secretKey)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptBytes]: Failed to decode or validate secret key: %v", err)
		return "", errors.Wrap(err, "", "failed to decode or validate secret key")
	}

	block, err := c.generateAESCipherBlock(key)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptBytes]: Failed to create AES cipher block: %v", err)
		return "", errors.Wrap(err, "", "failed to create AES cipher block")
	}

	nonce, err := c.generateRandomNonce()
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptBytes]: Failed to generate random nonce: %v", err)
		return "", errors.Wrap(err, "", "failed to generate random nonce")
	}

	aesGCM, err := c.generateGCMCipher(block)
	if err != nil {
		c.logger.Error(c.module, "", "[EncryptBytes]: Failed to create GCM cipher: %v", err)
		return "", errors.Wrap(err, "", "failed to create GCM cipher")
	}

	cipherText := aesGCM.Seal(nil, nonce, plainBytes, nil)
	result := append(nonce, cipherText...)
	encodedResult := base64.StdEncoding.EncodeToString(result)

	return encodedResult, nil
}

// DecryptBytes decrypts an AES-GCM encrypted string (base64 encoded) into a byte slice.
//
// Parameters:
//   - encryptedData string: The base64 encoded encrypted data (nonce + cipherText).
//   - secretKey string: The key used for decryption. It must be 32 bytes long for AES-256.
//
// Returns:
//   - []byte: The decrypted byte slice (plain data).
//   - error: Any error that occurs during decryption.
func (c *cryptographer) DecryptBytes(encryptedBytes, secretKey string) ([]byte, error) {
	key, err := c.decodeAndValidateSecretKey(secretKey)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptBytes]: Failed to decode or validate secret key: %v", err)
		return nil, errors.Wrap(err, "", "failed to decode or validate secret key")
	}

	decodedData, err := c.decodeBase64String(encryptedBytes)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptBytes]: Failed to decode base64 string: %v", err)
		return nil, errors.Wrap(err, "", "failed to decode base64 string")
	}

	const minLengthOfDecodedData int = 12
	if len(decodedData) < minLengthOfDecodedData {
		c.logger.Error(c.module, "", "[DecryptBytes]: Invalid encrypted data length: %d bytes", len(decodedData))
		return nil, errors.New(errors.ErrCodeInvalidInput, "encrypted data must be at least 12 bytes for nonce")
	}

	nonce := decodedData[:12]
	cipherText := decodedData[12:]

	block, err := c.generateAESCipherBlock(key)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptBytes]: Failed to create AES cipher block: %v", err)
		return nil, errors.Wrap(err, "", "failed to create AES cipher block")
	}

	aesGCM, err := c.generateGCMCipher(block)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptBytes]: Failed to create GCM cipher: %v", err)
		return nil, errors.Wrap(err, "", "failed to create GCM cipher")
	}

	plainBytes, err := c.decryptCipherText(aesGCM, nonce, cipherText)
	if err != nil {
		c.logger.Error(c.module, "", "[DecryptBytes]: Failed to decrypt cipher text: %v", err)
		return nil, errors.Wrap(err, "", "failed to decrypt cipher text")
	}

	return plainBytes, nil
}

// HashString takes a plain text string and returns a hashed
// version of it using bcrypt with the default cost.
//
// Parameters:
//   - plainStr string: The string to be encrypted.
//
// Returns:
//   - string: The encrypted string.
//   - error: Error if an error occurs hashing the string.
func (c *cryptographer) HashString(plainStr string) (string, error) {
	if plainStr == "" {
		return "", errors.New(errors.ErrCodeHashingFailed, "input string cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainStr), bcrypt.DefaultCost)
	if err != nil {
		c.logger.Error(c.module, "", "[HashString]: Failed to hash string: %v", err)
		return "", errors.New(errors.ErrCodeHashingFailed, "failed to hash string")
	}

	return string(hash), nil
}

// GenerateRandomString generates a cryptographically secure random string of the specified length.
//
// Parameters:
//   - length int: The desired length of the random string.
//
// Returns:
//   - string: The random generated string.
//   - error: An error if creating the random string fails.
func (c *cryptographer) GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		c.logger.Error(c.module, "", "[GenerateRandomString]: Failed to generate random string: %v", err)
		return "", errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate random string")
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (c *cryptographer) decodeAndValidateSecretKey(secretKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		c.logger.Error(c.module, "", "[decodeAndValidateSecretKey]: Failed to decode secret key: %v", err)
		return nil, errors.New(errors.ErrCodeInvalidInput, "failed to decode secret key")
	} else if len(key) != keyLength {
		c.logger.Error(c.module, "", "[decodeAndValidateSecretKey]: Invalid secret key length: %d bytes", len(key))
		return nil, errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
	}

	return key, nil
}

func (c *cryptographer) generateAESCipherBlock(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		c.logger.Error(c.module, "", "[generateAESCipherBlock]: Failed to create AES cipher block: %v", err)
		return nil, errors.New(errors.ErrCodeEncryptionFailed, "failed to create AES cipher block")
	}

	return block, nil
}

func (c *cryptographer) generateGCMCipher(block cipher.Block) (cipher.AEAD, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		c.logger.Error(c.module, "", "[generateGCMCipher]: Failed to create GCM cipher: %v", err)
		return nil, errors.New(errors.ErrCodeEncryptionFailed, "failed to create GCM cipher")
	}

	return aesGCM, nil
}

func (c *cryptographer) generateRandomNonce() ([]byte, error) {
	nonce := make([]byte, nonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		c.logger.Error(c.module, "", "[generateRandomNonce]: Failed to generate random nonce: %v", err)
		return nil, errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate random nonce")
	}

	return nonce, nil
}

func (c *cryptographer) decodeBase64String(cipherTextBase64 string) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		c.logger.Error(c.module, "", "[decodeBase64String]: Failed to decode base64 string: %v", err)
		return nil, errors.New(errors.ErrCodeInvalidInput, "failed to decode base64 string")
	}

	return cipherText, nil
}

func (c *cryptographer) decryptCipherText(aesGCM cipher.AEAD, nonce, cipherText []byte) ([]byte, error) {
	plainBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		c.logger.Error(c.module, "", "[decryptCipherText]: Failed to decrypt cipher text: %v", err)
		return nil, errors.New(errors.ErrCodeDecryptionFailed, "failed to decrypt cipher text")
	}

	return plainBytes, nil
}
