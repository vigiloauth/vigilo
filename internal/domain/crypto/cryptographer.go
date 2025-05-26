package domain

type Cryptographer interface {
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
	EncryptString(plainStr, secretKey string) (string, error)

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
	DecryptString(encryptedStr, secretKey string) (string, error)

	// EncryptBytes encrypts a given byte slice using AES-GCM mode.
	//
	// Parameters:
	//   - plainBytes []byte: The byte slice to encrypt.
	//   - secretKey []byte: The key used for encryption. It must be 32 bytes long for AES-256.
	//
	// Returns:
	//   - string: The base64-encoded encrypted data.
	//   - error: Any error that occurs during encryption.
	EncryptBytes(plainBytes []byte, secretKey string) (string, error)

	// DecryptBytes decrypts an AES-GCM encrypted string (base64 encoded) into a byte slice.
	//
	// Parameters:
	//   - encryptedData string: The base64 encoded encrypted data (nonce + cipherText).
	//   - secretKey string: The key used for decryption. It must be 32 bytes long for AES-256.
	//
	// Returns:
	//   - []byte: The decrypted byte slice (plain data).
	//   - error: Any error that occurs during decryption.
	DecryptBytes(encryptedBytes, secretKey string) ([]byte, error)

	// HashString takes a plain text string and returns a hashed
	// version of it using bcrypt with the default cost.
	//
	// Parameters:
	//   - plainStr string: The string to be encrypted.
	//
	// Returns:
	//   - string: The encrypted string.
	//   - error: Error if an error occurs hashing the string.
	HashString(plainStr string) (string, error)

	// GenerateRandomString generates a cryptographically secure random string of the specified length.
	//
	// Parameters:
	//   - length int: The desired length of the random string.
	//
	// Returns:
	//   - string: The random generated string.
	//   - error: An error if creating the random string fails.
	GenerateRandomString(length int) (string, error)
}
