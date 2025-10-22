package securecv

import (
	"field_cipher/libs/keychain"
	"field_cipher/models"
	"field_cipher/utils/cryptoutils"
	"field_cipher/utils/fileio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// SecureCV encrypts CV with per-field key management
type SecureCV struct {
	mu           sync.RWMutex
	keys         *keychain.KeyChain
	encrypted    map[string]*models.EncryptedData
	fieldKeyMap  map[string]string
}

// NewSecureCV creates a new SecureCV instance
func NewSecureCV() *SecureCV {
	return &SecureCV{
		keys:        keychain.NewKeyChain(),
		encrypted:   make(map[string]*models.EncryptedData),
		fieldKeyMap: make(map[string]string),
	}
}

// LoadCV loads and encrypts CV data
func (scv *SecureCV) LoadCV(cvData map[string]interface{}, mode string) error {
	scv.mu.Lock()
	defer scv.mu.Unlock()

	if cvData == nil {
		return fmt.Errorf("cv data is nil")
	}

	fmt.Printf("\nLoading %d CV fields in '%s' mode...\n", len(cvData), mode)

	for field, value := range cvData {
		var keyNode *models.KeyNode
		
		if mode == "multi" {
			keyNode = scv.keys.CreateKey()
		} else {
			if scv.keys.GetCurrentKey() == nil {
				keyNode = scv.keys.CreateKey()
			} else {
				keyNode = scv.keys.GetCurrentKey()
			}
		}

		// Encrypt field
		encryptedData, err := cryptoutils.EncryptData(value, keyNode.KeyBytes)
		if err != nil {
			return fmt.Errorf("failed to encrypt field %s: %v", field, err)
		}

		scv.encrypted[field] = encryptedData
		scv.fieldKeyMap[field] = keyNode.KeyID
		keyNode.EncryptedFields[field] = true
	}

	fmt.Printf("Encrypted %d fields with %d keys\n", len(cvData), scv.keys.Size())
	return nil
}

// GetField decrypts and retrieves field
func (scv *SecureCV) GetField(field string) (interface{}, error) {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	encryptedData, exists := scv.encrypted[field]
	if !exists {
		return nil, fmt.Errorf("field '%s' not found", field)
	}

	keyID, exists := scv.fieldKeyMap[field]
	if !exists {
		return nil, fmt.Errorf("no key found for field '%s'", field)
	}

	keyBytes, err := scv.keys.GetKeyBytes(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key for field '%s': %v", field, err)
	}

	return cryptoutils.DecryptData(encryptedData, keyBytes)
}

// RotateFieldKey rotates encryption key for specific field
func (scv *SecureCV) RotateFieldKey(field string) (string, error) {
	scv.mu.Lock()
	defer scv.mu.Unlock()

	encryptedData, exists := scv.encrypted[field]
	if !exists {
		return "", fmt.Errorf("field '%s' not found", field)
	}

	// Get old key
	oldKeyID, exists := scv.fieldKeyMap[field]
	if !exists {
		return "", fmt.Errorf("no key found for field '%s'", field)
	}

	oldKeyBytes, err := scv.keys.GetKeyBytes(oldKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to get old key: %v", err)
	}

	// Decrypt with old key
	plaintext, err := cryptoutils.DecryptData(encryptedData, oldKeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt with old key: %v", err)
	}

	// Create new key
	newKeyNode := scv.keys.CreateKey()

	// Re-encrypt with new key
	newEncryptedData, err := cryptoutils.EncryptData(plaintext, newKeyNode.KeyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to re-encrypt: %v", err)
	}

	// Update data structures
	scv.encrypted[field] = newEncryptedData
	scv.fieldKeyMap[field] = newKeyNode.KeyID

	// Update tracking
	oldNode := scv.keys.GetNode(oldKeyID)
	if oldNode != nil {
		delete(oldNode.EncryptedFields, field)
	}
	newKeyNode.EncryptedFields[field] = true

	fmt.Printf("Rotated key for '%s': %s... -> %s...\n", 
		field, oldKeyID[:8], newKeyNode.KeyID[:8])
	
	return newKeyNode.KeyID, nil
}

// GetShareableKey gets key info for sharing
func (scv *SecureCV) GetShareableKey(field string) (*models.ShareableKey, error) {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	keyID, exists := scv.fieldKeyMap[field]
	if !exists {
		return nil, fmt.Errorf("field '%s' not found", field)
	}

	node := scv.keys.GetNode(keyID)
	if node == nil || node.Revoked {
		return nil, fmt.Errorf("key not available or revoked")
	}

	fields := make([]string, 0, len(node.EncryptedFields))
	for f := range node.EncryptedFields {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	return &models.ShareableKey{
		KeyID:  keyID,
		Key:    base64.StdEncoding.EncodeToString(node.KeyBytes),
		Fields: fields,
	}, nil
}

// GetAllKeys gets all keys for full CV access
func (scv *SecureCV) GetAllKeys() *models.KeyManifest {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	manifest := &models.KeyManifest{
		Keys:     make(map[string]models.ShareableKey),
		FieldMap: make(map[string]string),
	}

	seenKeys := make(map[string]bool)

	for field, keyID := range scv.fieldKeyMap {
		manifest.FieldMap[field] = keyID
		
		if seenKeys[keyID] {
			continue
		}
		seenKeys[keyID] = true

		node := scv.keys.GetNode(keyID)
		if node != nil && !node.Revoked {
			fields := make([]string, 0, len(node.EncryptedFields))
			for f := range node.EncryptedFields {
				fields = append(fields, f)
			}
			sort.Strings(fields)

			manifest.Keys[keyID] = models.ShareableKey{
				KeyID:  keyID,
				Key:    base64.StdEncoding.EncodeToString(node.KeyBytes),
				Fields: fields,
			}
		}
	}

	return manifest
}

// SaveEncryptedCV saves encrypted CV to file
func (scv *SecureCV) SaveEncryptedCV(filename string) error {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	data := &models.EncryptedCV{
		EncryptedData: scv.encrypted,
		FieldKeyMap:   scv.fieldKeyMap,
	}
	data.Metadata.TotalFields = len(scv.encrypted)
	data.Metadata.TotalKeys = scv.keys.Size()

	return fileio.SaveJSON(filename, data)
}

// SaveKeys saves key manifest to file
func (scv *SecureCV) SaveKeys(filename string) error {
	manifest := scv.GetAllKeys()
	return fileio.SaveJSON(filename, manifest)
}

// LoadEncryptedCV loads encrypted CV from file
func (scv *SecureCV) LoadEncryptedCV(filename string) error {
	scv.mu.Lock()
	defer scv.mu.Unlock()

	var data models.EncryptedCV
	if err := fileio.LoadJSON(filename, &data); err != nil {
		return err
	}

	scv.encrypted = data.EncryptedData
	scv.fieldKeyMap = data.FieldKeyMap
	
	// Note: Keys need to be loaded separately for security
	fmt.Printf("Loaded encrypted CV with %d fields\n", data.Metadata.TotalFields)
	return nil
}

// DisplayKeys displays the current key chain
func (scv *SecureCV) DisplayKeys() {
	scv.keys.Display()
}

// GetStats returns statistics about the SecureCV instance
func (scv *SecureCV) GetStats() map[string]interface{} {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_fields"] = len(scv.encrypted)
	stats["total_keys"] = scv.keys.Size()
	
	keyStats := scv.keys.GetKeyStats()
	for k, v := range keyStats {
		stats[k] = v
	}
	
	return stats
}

// ExportField exports a specific field with its key
func (scv *SecureCV) ExportField(field string) (map[string]interface{}, error) {
	scv.mu.RLock()
	defer scv.mu.RUnlock()

	encryptedData, exists := scv.encrypted[field]
	if !exists {
		return nil, fmt.Errorf("field '%s' not found", field)
	}

	keyID, exists := scv.fieldKeyMap[field]
	if !exists {
		return nil, fmt.Errorf("no key found for field '%s'", field)
	}

	node := scv.keys.GetNode(keyID)
	if node == nil || node.Revoked {
		return nil, fmt.Errorf("key not available or revoked")
	}

	// Convert encrypted data to JSON
	encryptedJSON, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"field":          field,
		"encrypted_data": string(encryptedJSON),
		"key_id":         keyID,
		"key":            base64.StdEncoding.EncodeToString(node.KeyBytes),
	}, nil
}