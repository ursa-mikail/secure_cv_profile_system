package cryptoutils  

import (
	"field_cipher/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

// EncryptData encrypts data with AES-GCM
func EncryptData(plaintext interface{}, key []byte) (*models.EncryptedData, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Serialize to JSON
	var text string
	switch v := plaintext.(type) {
	case string:
		text = v
	default:
		jsonBytes, err := json.Marshal(plaintext)
		if err != nil {
			return nil, err
		}
		text = string(jsonBytes)
	}

	ciphertext := aesgcm.Seal(nil, nonce, []byte(text), nil)

	return &models.EncryptedData{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Type:       getTypeName(plaintext),
	}, nil
}

// DecryptData decrypts data with AES-GCM
func DecryptData(encrypted *models.EncryptedData, key []byte) (interface{}, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(encrypted.Nonce)
	if err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted.Ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if encrypted.Type == "map" || encrypted.Type == "slice" {
		var result interface{}
		if err := json.Unmarshal(plaintext, &result); err != nil {
			return nil, err
		}
		return result, nil
	}

	return string(plaintext), nil
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// GenerateRandomHex generates a random hexadecimal string
func GenerateRandomHex(n int) string {
	const letters = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[GenerateRandomBytes(1)[0]%byte(len(letters))]
	}
	return string(b)
}

// getTypeName returns the type name of the value
func getTypeName(v interface{}) string {
	switch v.(type) {
	case string:
		return "string"
	case map[string]interface{}:
		return "map"
	case []interface{}:
		return "slice"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// ValidateKey checks if a key is valid for AES encryption
func ValidateKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32: // AES-128, AES-192, AES-256
		return nil
	default:
		return fmt.Errorf("invalid key size: %d bytes (must be 16, 24, or 32 bytes)", len(key))
	}
}

// GenerateAESKey generates a new AES key of specified size
func GenerateAESKey(size int) ([]byte, error) {
	switch size {
	case 128, 192, 256:
		bytes := size / 8
		return GenerateRandomBytes(bytes), nil
	default:
		return nil, fmt.Errorf("invalid AES key size: %d (must be 128, 192, or 256)", size)
	}
}
