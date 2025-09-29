import json
import secrets
import base64
from typing import Dict, Optional, Any, List, Set
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time

# ============================================================================
# DOUBLY LINKED LIST FOR KEY MANAGEMENT
# ============================================================================

class KeyNode:
    """Node containing encryption key and metadata"""
    def __init__(self, key_id: str, key_bytes: bytes):
        self.key_id = key_id
        self.key_bytes = key_bytes
        self.timestamp = time.time()
        self.revoked = False
        self.encrypted_fields: Set[str] = set()
        self.prev: Optional['KeyNode'] = None
        self.next: Optional['KeyNode'] = None

class KeyChain:
    """Doubly linked list managing encryption keys"""
    def __init__(self):
        self.head: Optional[KeyNode] = None
        self.tail: Optional[KeyNode] = None
        self.current: Optional[KeyNode] = None
        self.key_map: Dict[str, KeyNode] = {}
        self.size = 0
    
    def create_key(self) -> KeyNode:
        """Generate new key and add to chain"""
        key_id = secrets.token_hex(16)
        key_bytes = secrets.token_bytes(32)  # AES-256
        node = KeyNode(key_id, key_bytes)
        
        if self.head is None:
            self.head = self.tail = node
        else:
            self.tail.next = node
            node.prev = self.tail
            self.tail = node
        
        self.current = node
        self.key_map[key_id] = node
        self.size += 1
        return node
    
    def get_key_bytes(self, key_id: str) -> Optional[bytes]:
        """Retrieve key bytes by ID"""
        node = self.key_map.get(key_id)
        if node and not node.revoked:
            return node.key_bytes
        return None
    
    def get_node(self, key_id: str) -> Optional[KeyNode]:
        """Retrieve key node by ID"""
        return self.key_map.get(key_id)
    
    def revoke_key(self, key_id: str) -> bool:
        """Mark key as revoked"""
        node = self.key_map.get(key_id)
        if node:
            node.revoked = True
            node.timestamp = time.time()
            return True
        return False
    
    def display(self):
        """Print key chain"""
        print(f"\n{'='*70}")
        print(f"KEY CHAIN ({self.size} keys)")
        print(f"{'='*70}")
        
        node = self.head
        pos = 0
        while node:
            status = "REVOKED" if node.revoked else "ACTIVE"
            current_marker = " [CURRENT]" if node == self.current else ""
            print(f"{pos}. {node.key_id[:12]}... - {status}{current_marker}")
            print(f"   Fields: {len(node.encrypted_fields)} - {list(node.encrypted_fields)[:3]}")
            node = node.next
            pos += 1
        print("="*70)

# ============================================================================
# SECURE CV PROFILE
# ============================================================================

class SecureCV:
    """Encrypt CV with per-field key management"""
    
    def __init__(self):
        self.keys = KeyChain()
        self.encrypted: Dict[str, Dict] = {}
        self.field_key_map: Dict[str, str] = {}
    
    def encrypt(self, plaintext: Any, key: bytes) -> Dict:
        """Encrypt data with AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        
        # Serialize to string
        text = json.dumps(plaintext) if not isinstance(plaintext, str) else plaintext
        ciphertext = aesgcm.encrypt(nonce, text.encode('utf-8'), b'')
        
        return {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "type": type(plaintext).__name__
        }
    
    def decrypt(self, encrypted: Dict, key: bytes) -> Optional[Any]:
        """Decrypt data with AES-GCM"""
        try:
            aesgcm = AESGCM(key)
            nonce = base64.b64decode(encrypted["nonce"])
            ciphertext = base64.b64decode(encrypted["ciphertext"])
            
            plaintext = aesgcm.decrypt(nonce, ciphertext, b'').decode('utf-8')
            
            if encrypted["type"] in ["list", "dict"]:
                return json.loads(plaintext)
            return plaintext
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def load_cv(self, cv_dict: Dict, mode: str = "single") -> bool:
        """
        Load and encrypt CV data
        mode: "single" = one key for all fields
              "multi" = one key per field
        """
        if not isinstance(cv_dict, dict):
            print(f"Error: Expected dict, got {type(cv_dict)}")
            return False
        
        print(f"\nLoading {len(cv_dict)} CV fields in '{mode}' mode...")
        
        for field, value in cv_dict.items():
            if mode == "multi":
                key_node = self.keys.create_key()
            else:
                if self.keys.current is None:
                    key_node = self.keys.create_key()
                else:
                    key_node = self.keys.current
            
            # Encrypt field
            encrypted_data = self.encrypt(value, key_node.key_bytes)
            self.encrypted[field] = encrypted_data
            self.field_key_map[field] = key_node.key_id
            key_node.encrypted_fields.add(field)
        
        print(f"Encrypted {len(cv_dict)} fields with {self.keys.size} keys")
        return True
    
    def get_field(self, field: str, key: bytes) -> Optional[Any]:
        """Decrypt and retrieve field"""
        if field not in self.encrypted:
            print(f"Field '{field}' not found")
            return None
        return self.decrypt(self.encrypted[field], key)
    
    def rotate_field_key(self, field: str) -> Optional[str]:
        """Rotate encryption key for specific field"""
        if field not in self.encrypted:
            print(f"Field '{field}' not found")
            return None
        
        # Get old key
        old_key_id = self.field_key_map[field]
        old_key = self.keys.get_key_bytes(old_key_id)
        if not old_key:
            print("Old key not available")
            return None
        
        # Decrypt with old key
        plaintext = self.decrypt(self.encrypted[field], old_key)
        if plaintext is None:
            return None
        
        # Create new key
        new_key_node = self.keys.create_key()
        
        # Re-encrypt with new key
        self.encrypted[field] = self.encrypt(plaintext, new_key_node.key_bytes)
        self.field_key_map[field] = new_key_node.key_id
        
        # Update tracking
        old_node = self.keys.get_node(old_key_id)
        if old_node:
            old_node.encrypted_fields.discard(field)
        new_key_node.encrypted_fields.add(field)
        
        print(f"Rotated key for '{field}': {old_key_id[:8]}... -> {new_key_node.key_id[:8]}...")
        return new_key_node.key_id
    
    def get_shareable_key(self, field: str) -> Optional[Dict]:
        """Get key info for sharing"""
        if field not in self.field_key_map:
            return None
        
        key_id = self.field_key_map[field]
        node = self.keys.get_node(key_id)
        if node and not node.revoked:
            return {
                "key_id": key_id,
                "key": base64.b64encode(node.key_bytes).decode(),
                "fields": list(node.encrypted_fields)
            }
        return None
    
    def get_all_keys(self) -> Dict:
        """Get all keys for full CV access"""
        unique_keys = {}
        for key_id in set(self.field_key_map.values()):
            node = self.keys.get_node(key_id)
            if node and not node.revoked:
                unique_keys[key_id] = {
                    "key": base64.b64encode(node.key_bytes).decode(),
                    "fields": list(node.encrypted_fields)
                }
        
        return {
            "keys": unique_keys,
            "field_map": self.field_key_map
        }
    
    def save_encrypted_cv(self, filename: str = "encrypted_cv.json"):
        """Save encrypted CV"""
        data = {
            "encrypted_data": self.encrypted,
            "field_key_map": self.field_key_map,
            "metadata": {
                "total_fields": len(self.encrypted),
                "total_keys": self.keys.size
            }
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Saved encrypted CV to {filename}")
    
    def save_keys(self, filename: str = "keys.json"):
        """Save key manifest"""
        with open(filename, 'w') as f:
            json.dump(self.get_all_keys(), f, indent=2)
        print(f"Saved keys to {filename}")

# ============================================================================
# DEMOS
# ============================================================================

def demo_single_key(cv_data: Dict):
    """One key encrypts all fields"""
    print("\n" + "="*70)
    print("DEMO 1: SINGLE KEY MODE")
    print("="*70)
    
    cv = SecureCV()
    cv.load_cv(cv_data, mode="single")
    cv.keys.display()
    
    cv.save_encrypted_cv("encrypted_cv_single.json")
    cv.save_keys("keys_single.json")
    
    print(f"\nTotal keys: {len(cv.get_all_keys()['keys'])}")
    return cv

def demo_multi_key(cv_data: Dict):
    """One key per field"""
    print("\n" + "="*70)
    print("DEMO 2: MULTI-KEY MODE")
    print("="*70)
    
    cv = SecureCV()
    cv.load_cv(cv_data, mode="multi")
    cv.keys.display()
    
    # Share specific field key
    name_key = cv.get_shareable_key("name")
    if name_key:
        print(f"\nShareable key for 'name': {name_key['key_id'][:12]}...")
    
    cv.save_encrypted_cv("encrypted_cv_multi.json")
    cv.save_keys("keys_multi.json")
    
    return cv

def demo_field_access(cv_data: Dict):
    """Access specific field with key"""
    print("\n" + "="*70)
    print("DEMO 3: FIELD ACCESS WITH KEYS")
    print("="*70)
    
    # Test with single key mode
    print("\n--- SINGLE KEY MODE ---")
    cv_single = SecureCV()
    cv_single.load_cv(cv_data, mode="single")
    
    # Get key for previous_experience
    key_info = cv_single.get_shareable_key("previous_experience")
    if key_info:
        print(f"\nKey for 'previous_experience': {key_info['key_id'][:16]}...")
        print(f"This key also unlocks: {key_info['fields'][:5]}")
        
        # Decrypt the field
        key_bytes = base64.b64decode(key_info['key'])
        decrypted = cv_single.get_field("previous_experience", key_bytes)
        print(f"\nDecrypted 'previous_experience':")
        print(json.dumps(decrypted, indent=2)[:300] + "...")
    
    # Test with multi-key mode
    print("\n\n--- MULTI KEY MODE ---")
    cv_multi = SecureCV()
    cv_multi.load_cv(cv_data, mode="multi")
    
    key_info = cv_multi.get_shareable_key("previous_experience")
    if key_info:
        print(f"\nKey for 'previous_experience': {key_info['key_id'][:16]}...")
        print(f"This key only unlocks: {key_info['fields']}")
        
        # Decrypt the field
        key_bytes = base64.b64decode(key_info['key'])
        decrypted = cv_multi.get_field("previous_experience", key_bytes)
        print(f"\nDecrypted 'previous_experience':")
        print(json.dumps(decrypted, indent=2)[:300] + "...")
    
    return cv_single, cv_multi

def demo_rotation(cv_data: Dict):
    """Key rotation with before/after decryption"""
    print("\n" + "="*70)
    print("DEMO 4: KEY ROTATION")
    print("="*70)
    
    cv = SecureCV()
    cv.load_cv(cv_data, mode="single")
    
    # Get original key
    print("\n--- BEFORE ROTATION ---")
    old_key_info = cv.get_shareable_key("email")
    if old_key_info:
        old_key_id = old_key_info['key_id']
        old_key_bytes = base64.b64decode(old_key_info['key'])
        print(f"Old key ID: {old_key_id[:16]}...")
        
        # Decrypt with old key
        email_before = cv.get_field("email", old_key_bytes)
        print(f"Decrypted email: {email_before}")
    
    cv.keys.display()
    
    # Rotate the key
    print("\n--- ROTATING KEY ---")
    new_key_id = cv.rotate_field_key("email")
    
    cv.keys.display()
    
    # Try old key (should fail)
    print("\n--- TESTING OLD KEY (should fail) ---")
    try:
        email_with_old = cv.get_field("email", old_key_bytes)
        print(f"Old key result: {email_with_old}")
        if email_with_old is None:
            print("OLD KEY CANNOT DECRYPT - Rotation successful!")
    except:
        print("OLD KEY FAILED - Rotation successful!")
    
    # Use new key (should work)
    print("\n--- TESTING NEW KEY (should work) ---")
    new_key_info = cv.get_shareable_key("email")
    if new_key_info:
        new_key_bytes = base64.b64decode(new_key_info['key'])
        print(f"New key ID: {new_key_info['key_id'][:16]}...")
        
        email_with_new = cv.get_field("email", new_key_bytes)
        print(f"Decrypted email: {email_with_new}")
        if email_with_new:
            print("NEW KEY WORKS - Rotation successful!")
    
    # Verify other fields still work with their keys
    print("\n--- TESTING OTHER FIELDS ---")
    name_key_info = cv.get_shareable_key("name")
    if name_key_info:
        name_key_bytes = base64.b64decode(name_key_info['key'])
        name = cv.get_field("name", name_key_bytes)
        print(f"Name (different key): {name}")
    
    return cv

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    # Load CV data
    try:
        with open("cv_data.json", 'r') as f:
            cv_data = json.load(f)
        print(f"Loaded {len(cv_data)} fields from cv_data.json")
    except FileNotFoundError:
        print("cv_data.json not found, using sample data")
        cv_data = {
            "name": "ursa major",
            "email": "ursa@walnuss.com",
            "phone": "C: (xxx)-xxx-xxxx",
            "current_position": "CTO at Walnuss"
        }
    
    # Run demos
    cv1 = demo_single_key(cv_data)
    cv2 = demo_multi_key(cv_data)
    cv_single, cv_multi = demo_field_access(cv_data)
    cv3 = demo_rotation(cv_data)
    
    print("\n" + "="*70)
    print("COMPLETE")
    print("="*70)
    print("""
Generated files:
- encrypted_cv_single.json (CV with 1 key)
- keys_single.json (1 key manifest)
- encrypted_cv_multi.json (CV with N keys)
- keys_multi.json (N key manifest)

Usage:
  cv = SecureCV()
  cv.load_cv(data, mode="single")  # or "multi"
  key_info = cv.get_shareable_key("email")
  cv.rotate_field_key("phone")
    """)

"""
Loaded 10 fields from cv_data.json

======================================================================
DEMO 1: SINGLE KEY MODE
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys

======================================================================
KEY CHAIN (1 keys)
======================================================================
0. cb9fa173dd5b... - ACTIVE [CURRENT]
   Fields: 10 - ['linkedin', 'email', 'skills']
======================================================================
Saved encrypted CV to encrypted_cv_single.json
Saved keys to keys_single.json

Total keys: 1

======================================================================
DEMO 2: MULTI-KEY MODE
======================================================================

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys

======================================================================
KEY CHAIN (10 keys)
======================================================================
0. a1338a5ede68... - ACTIVE
   Fields: 1 - ['name']
1. 11834f6c7f16... - ACTIVE
   Fields: 1 - ['phone']
2. 3e0b59343e89... - ACTIVE
   Fields: 1 - ['email']
3. 9fc44c4c7255... - ACTIVE
   Fields: 1 - ['linkedin']
4. ee71cf0c4176... - ACTIVE
   Fields: 1 - ['languages']
5. fe0c7438c913... - ACTIVE
   Fields: 1 - ['professional_summary']
6. 397c200c1b08... - ACTIVE
   Fields: 1 - ['skills']
7. 3d307eaa60f3... - ACTIVE
   Fields: 1 - ['current_position']
8. 5c72be3bfe41... - ACTIVE
   Fields: 1 - ['patents']
9. 82a6814d34f0... - ACTIVE [CURRENT]
   Fields: 1 - ['education']
======================================================================

Shareable key for 'name': a1338a5ede68...
Saved encrypted CV to encrypted_cv_multi.json
Saved keys to keys_multi.json

======================================================================
DEMO 3: FIELD ACCESS WITH KEYS
======================================================================

--- SINGLE KEY MODE ---

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys


--- MULTI KEY MODE ---

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys

======================================================================
DEMO 4: KEY ROTATION
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys

--- BEFORE ROTATION ---
Old key ID: 4ce56c729f2cc72a...
Decrypted email: Violet.tech@Violet.com

======================================================================
KEY CHAIN (1 keys)
======================================================================
0. 4ce56c729f2c... - ACTIVE [CURRENT]
   Fields: 10 - ['linkedin', 'email', 'skills']
======================================================================

--- ROTATING KEY ---
Rotated key for 'email': 4ce56c72... -> ef954ec8...

======================================================================
KEY CHAIN (2 keys)
======================================================================
0. 4ce56c729f2c... - ACTIVE
   Fields: 9 - ['linkedin', 'skills', 'education']
1. ef954ec8fbcb... - ACTIVE [CURRENT]
   Fields: 1 - ['email']
======================================================================

--- TESTING OLD KEY (should fail) ---
Decryption error: 
Old key result: None
OLD KEY CANNOT DECRYPT - Rotation successful!

--- TESTING NEW KEY (should work) ---
New key ID: ef954ec8fbcb697f...
Decrypted email: Violet.tech@Violet.com
NEW KEY WORKS - Rotation successful!

--- TESTING OTHER FIELDS ---
Name (different key): Violet K.

======================================================================
COMPLETE
======================================================================

Generated files:
- encrypted_cv_single.json (CV with 1 key)
- keys_single.json (1 key manifest)
- encrypted_cv_multi.json (CV with N keys)
- keys_multi.json (N key manifest)

Usage:
  cv = SecureCV()
  cv.load_cv(data, mode="single")  # or "multi"
  key_info = cv.get_shareable_key("email")
  cv.rotate_field_key("phone")

"""
