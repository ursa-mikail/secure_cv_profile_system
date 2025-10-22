package main

import (
    "field_cipher/tests"
)

func main() {
    // Run all test cases
    tests.RunAllTests()
    
    // Or run specific demonstrations
    tests.DemoSingleKey()
    tests.DemoMultiKey()
    tests.DemoKeyRotation()
}

/*
% go run main.go
Loaded data from cv_data.json
Loaded 10 fields from CV data

======================================================================
TEST: SINGLE KEY MODE
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
✅ CV loaded successfully in single key mode

======================================================================
KEY CHAIN (1 keys)
======================================================================
0. e2ab70693304... - ACTIVE [CURRENT]
   Fields: 10 - [education name professional_summary]
======================================================================

======================================================================
TEST: MULTI KEY MODE
======================================================================

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys
✅ CV loaded successfully in multi key mode

======================================================================
KEY CHAIN (10 keys)
======================================================================
0. ce89a1f70cd6... - ACTIVE
   Fields: 1 - [current_position]
1. cc87b86d5c3e... - ACTIVE
   Fields: 1 - [email]
2. acc4c5abcd17... - ACTIVE
   Fields: 1 - [linkedin]
3. 7f79faba5f54... - ACTIVE
   Fields: 1 - [skills]
4. c17e00e514b2... - ACTIVE
   Fields: 1 - [patents]
5. c00275e4e82d... - ACTIVE
   Fields: 1 - [education]
6. 5b121238d2dd... - ACTIVE
   Fields: 1 - [name]
7. ca43fbd7ae6e... - ACTIVE
   Fields: 1 - [phone]
8. a98033e75867... - ACTIVE
   Fields: 1 - [languages]
9. 2d6e43ece399... - ACTIVE [CURRENT]
   Fields: 1 - [professional_summary]
======================================================================

======================================================================
TEST: FIELD ACCESS
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
✅ Field 'name' decrypted successfully: Violet K.
✅ Field 'email' decrypted successfully: Violet.tech@Violet.com
✅ Field 'skills' decrypted successfully: C/C++, Java, Python, Rust, JavaScript, SQL, Swift, Kotlin, TensorFlow, AWS...

======================================================================
TEST: KEY ROTATION
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
Email before rotation: Violet.tech@Violet.com
Rotated key for 'email': bedf78ad... -> 8c71c06f...
✅ Key rotated successfully. New key ID: 8c71c06f84a50fd7...
✅ Email after rotation: Violet.tech@Violet.com
✅ Data integrity maintained after key rotation

======================================================================
TEST: SHAREABLE KEYS
======================================================================

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys
✅ Shareable key obtained for 'name':
   Key ID: 68a1920d26232c6c
   Fields accessible: [name]
   Key (base64): +/tEiTAU4gkrOCfaZLVj...

======================================================================
TEST: ERROR HANDLING
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
✅ Correctly handled non-existent field: field 'nonexistent_field' not found
✅ Correctly handled rotation of non-existent field: field 'nonexistent_field' not found

======================================================================
TEST: MULTIPLE ROTATIONS
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
Original email: Violet.tech@Violet.com
Rotated key for 'email': d7abfc77... -> d5f652cd...
✅ Rotation 1 successful. Key ID: d5f652cd96b093e6...
Rotated key for 'email': d5f652cd... -> f1a0be66...
✅ Rotation 2 successful. Key ID: f1a0be6633c27909...
Rotated key for 'email': f1a0be66... -> 9f66bd66...
✅ Rotation 3 successful. Key ID: 9f66bd6685c58dd3...
✅ Data integrity maintained after multiple rotations

======================================================================
TEST: SAVE AND LOAD
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
Saved data to test_encrypted_cv.json
✅ Encrypted CV saved successfully
Saved data to test_keys.json
✅ Keys saved successfully

======================================================================
TEST: GET ALL KEYS
======================================================================

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys
✅ Total unique keys: 10
✅ Total fields: 10
   Key 1d8919e9a5ff... manages 1 fields
   Key f81e485adf85... manages 1 fields
   Key dc374f21c82c... manages 1 fields
   Key aac5ffaa0d94... manages 1 fields
   Key d151506bf463... manages 1 fields
   Key ceae6f979a60... manages 1 fields
   Key 4b7871d5342c... manages 1 fields
   Key dee991446d2f... manages 1 fields
   Key 16861cfe9c25... manages 1 fields
   Key be8b59277a52... manages 1 fields

======================================================================
TEST: MIXED DATA TYPES
======================================================================

Loading 5 CV fields in 'multi' mode...
Encrypted 5 fields with 5 keys
✅ Mixed data types loaded successfully
   String field: Simple string
   Array field: [item1 item2 item3]
   Object field: map[count:100 nested:value]

======================================================================
TEST: PERFORMANCE
======================================================================

Loading 50 CV fields in 'multi' mode...
Encrypted 50 fields with 50 keys
✅ Loaded 50 fields in 149.625µs
   Total keys created: 50

======================================================================
TEST: KEY REVOCATION
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
ℹ️  Key revocation test - would need keychain revocation implementation

======================================================================
ALL TESTS COMPLETED SUCCESSFULLY!
======================================================================

======================================================================
DEMO: SINGLE KEY MODE
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys

======================================================================
KEY CHAIN (1 keys)
======================================================================
0. 055ea8b5736d... - ACTIVE [CURRENT]
   Fields: 10 - [phone email skills]
======================================================================
Saved data to demo_single_cv.json
Saved data to demo_single_keys.json

======================================================================
DEMO: MULTI KEY MODE
======================================================================

Loading 10 CV fields in 'multi' mode...
Encrypted 10 fields with 10 keys

======================================================================
KEY CHAIN (10 keys)
======================================================================
0. 152ecb6a13ef... - ACTIVE
   Fields: 1 - [education]
1. bca3d0388e8d... - ACTIVE
   Fields: 1 - [phone]
2. 9c9a192a2d35... - ACTIVE
   Fields: 1 - [skills]
3. 607cf70c8d1f... - ACTIVE
   Fields: 1 - [current_position]
4. 6225ae8e11d4... - ACTIVE
   Fields: 1 - [name]
5. 0adaa3eb0dfd... - ACTIVE
   Fields: 1 - [email]
6. 22d0150ecbec... - ACTIVE
   Fields: 1 - [linkedin]
7. 9b047bc242bb... - ACTIVE
   Fields: 1 - [languages]
8. d6a9d02649cc... - ACTIVE
   Fields: 1 - [professional_summary]
9. e3f3eac2a130... - ACTIVE [CURRENT]
   Fields: 1 - [patents]
======================================================================
Saved data to demo_multi_cv.json
Saved data to demo_multi_keys.json

======================================================================
DEMO: KEY ROTATION
======================================================================

Loading 10 CV fields in 'single' mode...
Encrypted 10 fields with 1 keys
Before rotation: Violet.tech@Violet.com
Rotated key for 'email': 5812d069... -> a7249390...
After rotation: Violet.tech@Violet.com
✅ Data integrity verified!

*/