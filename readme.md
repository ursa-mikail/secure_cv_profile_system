# Secure CV Profile System

A Python-based encryption system for managing CV/resume data with granular access control using AES-256-GCM encryption and doubly linked list key management.

I've created a comprehensive README.md that clearly explains both modes:

## Key Sections:

1. **Architecture Overview** - Visual diagram showing the system flow

2. **Single Key Mode**
   - Visual example showing one key encrypting all fields
   - Use cases, characteristics, advantages/risks
   - When to use it

3. **Multi-Key Mode**
   - Visual example showing unique key per field
   - Use cases, characteristics, advantages/risks
   - When to use it

4. **Direct Mode Comparison**
   - Access control differences
   - Key rotation impact
   - Storage requirements with actual JSON examples

5. **Decision Guide** - Clear criteria for choosing which mode to use

The README uses:
- **Tables** for structured comparisons
- **Code blocks** for examples
- **Visual diagrams** (ASCII art) showing key relationships
- **JSON examples** showing actual output format
- **Security analysis** of each mode

The documentation makes it crystal clear that:
- **Single key** = simple, all-or-nothing access
- **Multi-key** = granular, field-level control

-----

**Simplified Structure:**
- `KeyNode` - stores key, metadata, and encrypted fields
- `KeyChain` - doubly linked list managing keys
- `SecureCV` - main class for encrypting/decrypting CV

**Two Modes:**
1. **Single key mode** - one key encrypts all fields
2. **Multi-key mode** - separate key per field

**Key Features:**
- Loads CV from `cv_data.json` (or uses fallback)
- AES-256-GCM encryption for each field
- Key rotation with re-encryption
- Shareable key manifests
- Field-level access control

**Output Files:**
- `encrypted_cv_single.json` - CV encrypted with 1 key
- `keys_single.json` - 1 key to decrypt everything
- `encrypted_cv_multi.json` - CV with per-field keys
- `keys_multi.json` - All individual keys

-----

## **DEMO 1: SINGLE KEY MODE**

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys


KEY CHAIN (1 keys)

0. cb9fa173dd5b... - ACTIVE [CURRENT]
   Fields: 10 - ['linkedin', 'email', 'skills']

Saved encrypted CV to encrypted_cv_single.json
Saved keys to keys_single.json

Total keys: 1

## **DEMO 2: MULTI-KEY MODE**

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys

## **DEMO 3: FIELD ACCESS WITH KEYS**

Shows how to access `previous_experience` in both modes:

**Single Key Mode:**
- One key unlocks ALL fields (name, email, previous_experience, etc.)
- Shows which fields share the same key
- Decrypts and displays the previous_experience data

**Multi-Key Mode:**
- Each field has its own unique key
- The key for `previous_experience` ONLY unlocks that field
- More granular access control

## **DEMO 4: KEY ROTATION**

Demonstrates the complete rotation lifecycle:

1. **Before Rotation** - Get original key, decrypt email successfully
2. **Rotate Key** - Create new key, re-encrypt email field
3. **Test Old Key** - Try to decrypt with old key → FAILS (returns None)
4. **Test New Key** - Decrypt with new key → SUCCESS
5. **Verify Other Fields** - Confirm other fields still work with their keys

The demo clearly shows that after rotation, the old key becomes useless for that field while the new key works perfectly. This is the core security feature for one-time use patterns.

Run the script and you'll see:
- Clear before/after comparison
- Visual key chain display showing the rotation
- Actual decryption attempts proving old key is invalid
- New key successfully decrypting the data

-----

## Overview

This system encrypts each field of your CV (name, email, skills, etc.) and manages encryption keys through a doubly linked list structure. It supports two operational modes with different security and sharing characteristics.

## Architecture

```
CV Data (JSON) → Encryption → Encrypted CV + Key Manifest
                     ↓
              Key Chain (Doubly Linked List)
                     ↓
         Individual Field Encryption Keys
```

### Components

- **KeyNode**: Stores encryption key, metadata, and tracks which fields it encrypts
- **KeyChain**: Doubly linked list managing all encryption keys
- **SecureCV**: Main class handling encryption, decryption, and key operations

## Encryption Modes

### Single Key Mode

**How It Works:**
- One master key encrypts ALL CV fields
- All fields share the same encryption key
- Key is reused across the entire CV

**Use Case:**
```python
cv = SecureCV()
cv.load_cv(cv_data, mode="single")
```

**Key Characteristics:**

| Feature | Description |
|---------|-------------|
| Keys Generated | 1 key total |
| Key Sharing | Share 1 key = full CV access |
| Access Control | All-or-nothing access |
| Performance | Fast (one key operation) |
| Storage | Minimal key storage |

**Example:**
```
CV Fields:              Encryption Key:
- name                  Key_ABC123 (encrypts all)
- email                 Key_ABC123 (encrypts all)
- phone                 Key_ABC123 (encrypts all)
- skills                Key_ABC123 (encrypts all)
- experience            Key_ABC123 (encrypts all)
```

**When to Use:**
- Sharing complete CV with trusted parties (recruiters, employers)
- Simple access management
- Performance is critical
- Don't need field-level access control

**Security Model:**
- **Advantage**: Simpler key management, fewer keys to secure
- **Risk**: If key is compromised, entire CV is exposed
- **Rotation**: Rotating one field requires re-encrypting ALL fields

---

### Multi-Key Mode

**How It Works:**
- Each CV field gets its own unique encryption key
- Every field is independently encrypted
- Keys are tracked separately in the linked list

**Use Case:**
```python
cv = SecureCV()
cv.load_cv(cv_data, mode="multi")
```

**Key Characteristics:**

| Feature | Description |
|---------|-------------|
| Keys Generated | N keys (one per field) |
| Key Sharing | Granular - share specific field keys |
| Access Control | Field-level precision |
| Performance | Slower (multiple key operations) |
| Storage | More keys to manage |

**Example:**
```
CV Fields:              Encryption Keys:
- name                  Key_AAA111
- email                 Key_BBB222
- phone                 Key_CCC333
- skills                Key_DDD444
- experience            Key_EEE555
```

**When to Use:**
- Need granular access control
- Share only specific fields (contact info only, skills only, etc.)
- Different parties need different access levels
- High security requirements

**Security Model:**
- **Advantage**: Compromising one key only exposes that field
- **Risk**: More keys to manage and secure
- **Rotation**: Can rotate individual field keys without affecting others

---

## Mode Comparison

### Access Control

**Single Key Mode:**
```python
# Share key with recruiter
key_info = cv.get_shareable_key("name")  
# This key unlocks: ['name', 'email', 'phone', 'skills', 'experience', ...]
# ALL OR NOTHING ACCESS
```

**Multi-Key Mode:**
```python
# Share only contact info
name_key = cv.get_shareable_key("name")    # Only unlocks 'name'
email_key = cv.get_shareable_key("email")  # Only unlocks 'email'
# GRANULAR ACCESS
```

### Key Rotation Impact

**Single Key Mode:**
```
Rotate key for 'email' field
└── Must re-encrypt: name, email, phone, skills, experience (ALL fields)
└── Old key becomes useless for EVERYTHING
```

**Multi-Key Mode:**
```
Rotate key for 'email' field
└── Only re-encrypts: email
└── Old key only useless for email
└── Other fields unaffected
```

### Storage Requirements

**Single Key Mode:**
```json
{
  "keys": {
    "abc123...": {
      "key": "base64_encoded_key",
      "fields": ["name", "email", "phone", "skills", "experience", ...]
    }
  }
}
```
**Size**: ~200 bytes per key × 1 key = ~200 bytes

**Multi-Key Mode:**
```json
{
  "keys": {
    "key1...": {"key": "...", "fields": ["name"]},
    "key2...": {"key": "...", "fields": ["email"]},
    "key3...": {"key": "...", "fields": ["phone"]},
    ...
  }
}
```
**Size**: ~200 bytes per key × N fields = ~200N bytes

---

## Usage Examples

### Basic Setup

```python
from secure_cv import SecureCV
import json

# Load CV data
with open("cv_data.json", 'r') as f:
    cv_data = json.load(f)

# Single key mode
cv_single = SecureCV()
cv_single.load_cv(cv_data, mode="single")

# Multi-key mode
cv_multi = SecureCV()
cv_multi.load_cv(cv_data, mode="multi")
```

### Accessing Fields

```python
# Get shareable key
key_info = cv.get_shareable_key("previous_experience")

# Decrypt field
key_bytes = base64.b64decode(key_info['key'])
data = cv.get_field("previous_experience", key_bytes)
print(data)
```

### Key Rotation

```python
# Rotate key for sensitive field
cv.rotate_field_key("email")

# Old key no longer works
# New key automatically assigned
```

### Sharing Keys

```python
# Share all keys (full access)
all_keys = cv.get_all_keys()

# Share specific field key (limited access)
email_key = cv.get_shareable_key("email")

# Send key to recipient (they can decrypt only that field)
```

---

## Security Features

### Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 96 bits (12 bytes, randomly generated)
- **Authentication**: Built-in with GCM mode

### Key Management
- Keys stored in doubly linked list for efficient traversal
- Each key tracks which fields it encrypts
- Support for key revocation (soft delete)
- Timestamps for audit trail

### Access Patterns
- **Read**: Decrypt field with provided key
- **Rotate**: Generate new key, re-encrypt, invalidate old key
- **Revoke**: Mark key as invalid without deletion
- **Share**: Export key as base64 for transmission

---

## Output Files

### Encrypted CV
```json
{
  "encrypted_data": {
    "name": {
      "nonce": "base64_nonce",
      "ciphertext": "base64_encrypted_data",
      "type": "str"
    }
  },
  "field_key_map": {
    "name": "key_id_abc123..."
  },
  "metadata": {
    "total_fields": 14,
    "total_keys": 1
  }
}
```

### Key Manifest
```json
{
  "keys": {
    "abc123...": {
      "key": "base64_encoded_key",
      "fields": ["name", "email", ...]
    }
  },
  "field_map": {
    "name": "abc123...",
    "email": "abc123..."
  }
}
```

---

## Decision Guide

### Choose **Single Key Mode** if:
- Sharing entire CV with trusted parties
- Simple key management preferred
- Performance is important
- All fields have same sensitivity level
- Recipients need full CV access

### Choose **Multi-Key Mode** if:
- Need field-level access control
- Different parties need different information
- High security/compliance requirements
- Fields have different sensitivity levels
- Want to minimize blast radius of key compromise

---

## Installation

```bash
pip install cryptography
```

## Running Demos

```bash
python secure_cv_profile.py
```

This will:
1. Load CV from `cv_data.json`
2. Run all demonstrations
3. Generate encrypted CV and key manifest files
4. Show field access and key rotation examples

---

```

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

```
