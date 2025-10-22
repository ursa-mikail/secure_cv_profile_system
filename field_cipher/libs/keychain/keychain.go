package keychain

import (
	"field_cipher/models"
	"field_cipher/utils/cryptoutils"  
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// KeyChain manages encryption keys using a doubly linked list
type KeyChain struct {
	mu      sync.RWMutex
	head    *models.KeyNode
	tail    *models.KeyNode
	current *models.KeyNode
	keyMap  map[string]*models.KeyNode
	size    int
}

// NewKeyChain creates a new KeyChain
func NewKeyChain() *KeyChain {
	return &KeyChain{
		keyMap: make(map[string]*models.KeyNode),
	}
}

// CreateKey generates new key and adds to chain
func (kc *KeyChain) CreateKey() *models.KeyNode {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	keyID := cryptoutils.GenerateRandomHex(16)
	keyBytes := cryptoutils.GenerateRandomBytes(32) // AES-256

	node := &models.KeyNode{
		KeyID:           keyID,
		KeyBytes:        keyBytes,
		Timestamp:       time.Now().Unix(),
		EncryptedFields: make(map[string]bool),
	}

	if kc.head == nil {
		kc.head = node
		kc.tail = node
	} else {
		kc.tail.Next = node
		node.Prev = kc.tail
		kc.tail = node
	}

	kc.current = node
	kc.keyMap[keyID] = node
	kc.size++

	return node
}

// GetKeyBytes retrieves key bytes by ID
func (kc *KeyChain) GetKeyBytes(keyID string) ([]byte, error) {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	node, exists := kc.keyMap[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}
	if node.Revoked {
		return nil, fmt.Errorf("key revoked")
	}
	return node.KeyBytes, nil
}

// GetNode retrieves key node by ID
func (kc *KeyChain) GetNode(keyID string) *models.KeyNode {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.keyMap[keyID]
}

// RevokeKey marks key as revoked
func (kc *KeyChain) RevokeKey(keyID string) error {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	node, exists := kc.keyMap[keyID]
	if !exists {
		return fmt.Errorf("key not found")
	}

	node.Revoked = true
	node.Timestamp = time.Now().Unix()
	return nil
}

// GetCurrentKey returns the current active key
func (kc *KeyChain) GetCurrentKey() *models.KeyNode {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.current
}

// SetCurrentKey sets the current active key
func (kc *KeyChain) SetCurrentKey(keyID string) error {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	node, exists := kc.keyMap[keyID]
	if !exists {
		return fmt.Errorf("key not found")
	}
	if node.Revoked {
		return fmt.Errorf("key is revoked")
	}

	kc.current = node
	return nil
}

// GetAllKeys returns all non-revoked keys
func (kc *KeyChain) GetAllKeys() []*models.KeyNode {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	keys := make([]*models.KeyNode, 0)
	node := kc.head
	for node != nil {
		if !node.Revoked {
			keys = append(keys, node)
		}
		node = node.Next
	}
	return keys
}

// GetRevokedKeys returns all revoked keys
func (kc *KeyChain) GetRevokedKeys() []*models.KeyNode {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	keys := make([]*models.KeyNode, 0)
	node := kc.head
	for node != nil {
		if node.Revoked {
			keys = append(keys, node)
		}
		node = node.Next
	}
	return keys
}

// Size returns the number of keys in the chain
func (kc *KeyChain) Size() int {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	return kc.size
}

// Display prints key chain
func (kc *KeyChain) Display() {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("KEY CHAIN (%d keys)\n", kc.size)
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	node := kc.head
	pos := 0
	for node != nil {
		node.Display(pos, node == kc.current)
		node = node.Next
		pos++
	}
	fmt.Printf("%s\n", strings.Repeat("=", 70))
}

// GetKeyStats returns statistics about the key chain
func (kc *KeyChain) GetKeyStats() map[string]interface{} {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_keys"] = kc.size
	
	active := 0
	revoked := 0
	node := kc.head
	for node != nil {
		if node.Revoked {
			revoked++
		} else {
			active++
		}
		node = node.Next
	}
	
	stats["active_keys"] = active
	stats["revoked_keys"] = revoked
	stats["current_key_id"] = ""
	if kc.current != nil {
		stats["current_key_id"] = kc.current.KeyID
	}
	
	return stats
}

// CleanupRevokedKeys removes revoked keys older than specified duration
func (kc *KeyChain) CleanupRevokedKeys(maxAge time.Duration) int {
	kc.mu.Lock()
	defer kc.mu.Unlock()

	cutoff := time.Now().Add(-maxAge).Unix()
	removed := 0

	// Start from head and remove old revoked keys
	node := kc.head
	for node != nil {
		next := node.Next
		
		if node.Revoked && node.Timestamp < cutoff {
			// Remove node from linked list
			if node.Prev != nil {
				node.Prev.Next = node.Next
			} else {
				kc.head = node.Next
			}
			
			if node.Next != nil {
				node.Next.Prev = node.Prev
			} else {
				kc.tail = node.Prev
			}
			
			// Remove from map
			delete(kc.keyMap, node.KeyID)
			kc.size--
			removed++
			
			// Update current if it was removed
			if kc.current == node {
				kc.current = kc.tail
			}
		}
		
		node = next
	}

	return removed
}

// ExportKeyChain exports the key chain for backup
func (kc *KeyChain) ExportKeyChain() *models.KeyManifest {
	kc.mu.RLock()
	defer kc.mu.RUnlock()

	manifest := &models.KeyManifest{
		Keys:     make(map[string]models.ShareableKey),
		FieldMap: make(map[string]string),
	}

	// Since we can't export actual keys for security reasons,
	// we export metadata only
	node := kc.head
	for node != nil {
		if !node.Revoked {
			fields := make([]string, 0, len(node.EncryptedFields))
			for field := range node.EncryptedFields {
				fields = append(fields, field)
				manifest.FieldMap[field] = node.KeyID
			}
			sort.Strings(fields)

			manifest.Keys[node.KeyID] = models.ShareableKey{
				KeyID: node.KeyID,
				Fields: fields,
			}
		}
		node = node.Next
	}

	return manifest
}
