# Field Cipher - Secure CV Encryption System
A Go-based encryption system that provides field-level encryption for CV/resume data with flexible key management and rotation capabilities.

## Overview
This system allows you to encrypt individual fields of sensitive data (like a CV) with the ability to:

- Use single key mode (all fields encrypted with one key)
- Use multi-key mode (each field encrypted with its own key)
- Rotate keys for specific fields without data loss
- Share access to specific fields securely

## Key Features
- Field-Level Encryption: Encrypt individual data fields separately
- Flexible Key Modes: Single key for all fields or separate keys per field
- Key Rotation: Rotate encryption keys for specific fields while maintaining data accessibility
- Secure Crypto: Uses AES-GCM encryption for authenticated encryption
- Key Management: Doubly linked list for efficient key tracking and management
- File Persistence: Save encrypted data and key manifests to JSON files


```
# Initialize module
go mod init field_cipher

# Run the main application
go run main.go

# Run specific packages
go run ./tests/test_cases.go

# Build the entire project
go build
```

```
field_cipher/
├── main.go                 # Main application entry point
├── libs/
│   ├── keychain/          # Key management with doubly linked list
│   └── securecv/          # Main CV encryption logic
├── models/                # Data structures and models
├── utils/
│   ├── cryptoutils/       # Cryptographic functions
│   └── fileio/           # File I/O operations
└── tests/                 # Comprehensive test suite
```

### Multi-Key Mode for Granular Access

```
// Each field gets its own encryption key
cv.LoadCV(cvData, "multi")

// Share specific field keys
emailKey, _ := cv.GetShareableKey("email")
fmt.Printf("Email key ID: %s\n", emailKey.KeyID)

// This key only decrypts the email field
```

### Key Rotation

```
// Rotate key for sensitive field
oldEmail, _ := cv.GetField("email")
newKeyID, _ := cv.RotateFieldKey("email")
newEmail, _ := cv.GetField("email")

// Data remains the same, key changes
fmt.Printf("Data unchanged: %v\n", oldEmail == newEmail)
```

## API Reference
### SecureCV Methods

```
NewSecureCV() - Create new instance

LoadCV(data, mode) - Load and encrypt CV data ("single" or "multi" mode)

GetField(field) - Decrypt and retrieve field value

RotateFieldKey(field) - Rotate encryption key for specific field

GetShareableKey(field) - Get key information for sharing

GetAllKeys() - Get all keys and field mappings

SaveEncryptedCV(filename) - Save encrypted data to file

SaveKeys(filename) - Save key manifest to file

DisplayKeys() - Show current key chain
```

### File Outputs
```
encrypted_cv.json - Encrypted field data with metadata

keys.json - Key manifest with field mappings

Test files with test_ prefix during development
```