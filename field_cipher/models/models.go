package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// KeyNode represents a node containing encryption key and metadata
type KeyNode struct {
	KeyID            string
	KeyBytes         []byte
	Timestamp        int64
	Revoked          bool
	EncryptedFields  map[string]bool
	Prev             *KeyNode
	Next             *KeyNode
}

// EncryptedData represents encrypted field data
type EncryptedData struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Type       string `json:"type"`
}

// ShareableKey represents key information for sharing
type ShareableKey struct {
	KeyID string   `json:"key_id"`
	Key   string   `json:"key"`
	Fields []string `json:"fields"`
}

// KeyManifest represents all keys for full CV access
type KeyManifest struct {
	Keys     map[string]ShareableKey `json:"keys"`
	FieldMap map[string]string       `json:"field_map"`
}

// EncryptedCV represents the complete encrypted CV structure
type EncryptedCV struct {
	EncryptedData map[string]*EncryptedData `json:"encrypted_data"` // Changed to pointer
	FieldKeyMap   map[string]string        `json:"field_key_map"`
	Metadata      struct {
		TotalFields int `json:"total_fields"`
		TotalKeys   int `json:"total_keys"`
	} `json:"metadata"`
}

// Display prints the key node information
func (kn *KeyNode) Display(position int, isCurrent bool) {
	status := "ACTIVE"
	if kn.Revoked {
		status = "REVOKED"
	}
	currentMarker := ""
	if isCurrent {
		currentMarker = " [CURRENT]"
	}

	fields := make([]string, 0, len(kn.EncryptedFields))
	for field := range kn.EncryptedFields {
		fields = append(fields, field)
	}

	fmt.Printf("%d. %s... - %s%s\n", position, kn.KeyID[:12], status, currentMarker)
	fmt.Printf("   Fields: %d - %v\n", len(fields), fields[:min(3, len(fields))])
}

// ToJSON converts EncryptedData to JSON string
func (ed *EncryptedData) ToJSON() (string, error) {
	data, err := json.Marshal(ed)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON populates EncryptedData from JSON string
func (ed *EncryptedData) FromJSON(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), ed)
}

// GetCreationTime returns the creation time of the key
func (kn *KeyNode) GetCreationTime() time.Time {
	return time.Unix(kn.Timestamp, 0)
}

// IsExpired checks if the key is expired based on duration
func (kn *KeyNode) IsExpired(duration time.Duration) bool {
	return time.Since(kn.GetCreationTime()) > duration
}

// helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
