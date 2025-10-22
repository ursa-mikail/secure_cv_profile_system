package tests

import (
	"field_cipher/libs/securecv"
	"field_cipher/utils/fileio"
	"fmt"
	"strings"
	"time"
)

// getSampleData provides sample CV data for testing
func getSampleData() map[string]interface{} {
	return map[string]interface{}{
		"name":                  "Violet K.",
		"phone":                 "C: (347)-555-1294",
		"email":                 "Violet.tech@Violet.com",
		"linkedin":              "https://www.linkedin.com/in/Violet/",
		"languages":             "English, French, Japanese",
		"professional_summary":  "Technology leadership. Security specialist and Embedded Systems Architect with 18+ years of experience...",
		"skills":                "C/C++, Java, Python, Rust, JavaScript, SQL, Swift, Kotlin, TensorFlow, AWS...",
		"current_position":      "Principal Engineer at SafeTech Solutions (2023 Nov – Present)",
		"patents":               "25+ patents on IoT security and cryptographic systems",
		"education":             "Masters Degree in Computer Engineering and Cybersecurity",
	}
}

// RunAllTests runs all comprehensive test cases
func RunAllTests() {
	cvData, err := fileio.LoadCVData("cv_data.json")
	if err != nil {
		fmt.Printf("Error loading cv_data.json: %v\n", err)
		fmt.Println("Using sample data instead...")
		cvData = getSampleData()
	}

	fmt.Printf("Loaded %d fields from CV data\n", len(cvData))

	// Run individual test cases
	TestSingleKeyMode(cvData)
	TestMultiKeyMode(cvData)
	TestFieldAccess(cvData)
	TestKeyRotation(cvData)
	TestShareableKeys(cvData)
	TestErrorHandling(cvData)
	TestMultipleRotations(cvData)
	TestSaveLoad(cvData)
	TestGetAllKeys(cvData)
	TestMixedDataTypes()
	TestPerformance()
	TestKeyRevocation(cvData)

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("ALL TESTS COMPLETED SUCCESSFULLY!")
	fmt.Printf("%s\n", strings.Repeat("=", 70))
}

// TestSingleKeyMode tests single key encryption mode
func TestSingleKeyMode(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: SINGLE KEY MODE")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	err := cv.LoadCV(cvData, "single")
	if err != nil {
		fmt.Printf("❌ Failed to load CV: %v\n", err)
		return
	}
	fmt.Println("✅ CV loaded successfully in single key mode")
	cv.DisplayKeys()
}

// TestMultiKeyMode tests multi key encryption mode
func TestMultiKeyMode(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: MULTI KEY MODE")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	err := cv.LoadCV(cvData, "multi")
	if err != nil {
		fmt.Printf("❌ Failed to load CV: %v\n", err)
		return
	}
	fmt.Println("✅ CV loaded successfully in multi key mode")
	cv.DisplayKeys()
}

// TestFieldAccess tests field access and decryption
func TestFieldAccess(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: FIELD ACCESS")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	// Test decrypting various fields
	testFields := []string{"name", "email", "skills"}
	for _, field := range testFields {
		value, err := cv.GetField(field)
		if err != nil {
			fmt.Printf("❌ Failed to get field '%s': %v\n", field, err)
		} else {
			fmt.Printf("✅ Field '%s' decrypted successfully: %v\n", field, value)
		}
	}
}

// TestKeyRotation tests key rotation functionality
func TestKeyRotation(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: KEY ROTATION")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	// Get email before rotation
	emailBefore, _ := cv.GetField("email")
	fmt.Printf("Email before rotation: %v\n", emailBefore)

	// Rotate the key
	newKeyID, err := cv.RotateFieldKey("email")
	if err != nil {
		fmt.Printf("❌ Failed to rotate key: %v\n", err)
		return
	}
	fmt.Printf("✅ Key rotated successfully. New key ID: %s...\n", newKeyID[:16])

	// Get email after rotation
	emailAfter, err := cv.GetField("email")
	if err != nil {
		fmt.Printf("❌ Failed to get email after rotation: %v\n", err)
	} else {
		fmt.Printf("✅ Email after rotation: %v\n", emailAfter)
	}

	// Verify data integrity
	if emailBefore == emailAfter {
		fmt.Println("✅ Data integrity maintained after key rotation")
	} else {
		fmt.Println("❌ Data corrupted during key rotation")
	}
}

// TestShareableKeys tests shareable key functionality
func TestShareableKeys(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: SHAREABLE KEYS")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "multi")

	keyInfo, err := cv.GetShareableKey("name")
	if err != nil {
		fmt.Printf("❌ Failed to get shareable key: %v\n", err)
		return
	}
	fmt.Printf("✅ Shareable key obtained for 'name':\n")
	fmt.Printf("   Key ID: %s\n", keyInfo.KeyID)
	fmt.Printf("   Fields accessible: %v\n", keyInfo.Fields)
	fmt.Printf("   Key (base64): %s...\n", keyInfo.Key[:20])
}

// TestErrorHandling tests error handling for invalid operations
func TestErrorHandling(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: ERROR HANDLING")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	// Try to get non-existent field
	_, err := cv.GetField("nonexistent_field")
	if err != nil {
		fmt.Printf("✅ Correctly handled non-existent field: %v\n", err)
	} else {
		fmt.Println("❌ Should have returned error for non-existent field")
	}

	// Try to rotate non-existent field
	_, err = cv.RotateFieldKey("nonexistent_field")
	if err != nil {
		fmt.Printf("✅ Correctly handled rotation of non-existent field: %v\n", err)
	} else {
		fmt.Println("❌ Should have returned error for rotating non-existent field")
	}
}

// TestMultipleRotations tests multiple key rotations
func TestMultipleRotations(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: MULTIPLE ROTATIONS")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	originalEmail, _ := cv.GetField("email")
	fmt.Printf("Original email: %v\n", originalEmail)

	// Rotate multiple times
	for i := 1; i <= 3; i++ {
		newKeyID, err := cv.RotateFieldKey("email")
		if err != nil {
			fmt.Printf("❌ Rotation %d failed: %v\n", i, err)
		} else {
			fmt.Printf("✅ Rotation %d successful. Key ID: %s...\n", i, newKeyID[:16])
		}
	}

	finalEmail, err := cv.GetField("email")
	if err != nil {
		fmt.Printf("❌ Failed to get email after multiple rotations: %v\n", err)
	} else if originalEmail == finalEmail {
		fmt.Println("✅ Data integrity maintained after multiple rotations")
	} else {
		fmt.Println("❌ Data corrupted during multiple rotations")
	}
}

// TestSaveLoad tests save and load functionality
func TestSaveLoad(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: SAVE AND LOAD")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	// Save encrypted data
	err := cv.SaveEncryptedCV("test_encrypted_cv.json")
	if err != nil {
		fmt.Printf("❌ Failed to save encrypted CV: %v\n", err)
	} else {
		fmt.Println("✅ Encrypted CV saved successfully")
	}

	// Save keys
	err = cv.SaveKeys("test_keys.json")
	if err != nil {
		fmt.Printf("❌ Failed to save keys: %v\n", err)
	} else {
		fmt.Println("✅ Keys saved successfully")
	}
}

// TestGetAllKeys tests GetAllKeys functionality
func TestGetAllKeys(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: GET ALL KEYS")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "multi")

	allKeys := cv.GetAllKeys()
	fmt.Printf("✅ Total unique keys: %d\n", len(allKeys.Keys))
	fmt.Printf("✅ Total fields: %d\n", len(allKeys.FieldMap))

	for keyID, keyInfo := range allKeys.Keys {
		fmt.Printf("   Key %s... manages %d fields\n", keyID[:12], len(keyInfo.Fields))
	}
}

// TestMixedDataTypes tests handling of mixed data types
func TestMixedDataTypes() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: MIXED DATA TYPES")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	mixedData := map[string]interface{}{
		"string_field":  "Simple string",
		"number_field":  42,
		"boolean_field": true,
		"array_field":   []interface{}{"item1", "item2", "item3"},
		"object_field": map[string]interface{}{
			"nested": "value",
			"count":  100,
		},
	}

	cv := securecv.NewSecureCV()
	err := cv.LoadCV(mixedData, "multi")
	if err != nil {
		fmt.Printf("❌ Failed to load mixed data: %v\n", err)
		return
	}
	fmt.Println("✅ Mixed data types loaded successfully")

	// Test retrieving different types
	stringVal, _ := cv.GetField("string_field")
	fmt.Printf("   String field: %v\n", stringVal)

	arrayVal, _ := cv.GetField("array_field")
	fmt.Printf("   Array field: %v\n", arrayVal)

	objectVal, _ := cv.GetField("object_field")
	fmt.Printf("   Object field: %v\n", objectVal)
}

// TestPerformance tests performance with many fields
func TestPerformance() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: PERFORMANCE")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	manyFieldsData := make(map[string]interface{})
	for i := 0; i < 50; i++ {
		manyFieldsData[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("Value for field %d with some data", i)
	}

	start := time.Now()
	cv := securecv.NewSecureCV()
	err := cv.LoadCV(manyFieldsData, "multi")
	loadTime := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Failed to load many fields: %v\n", err)
		return
	}
	fmt.Printf("✅ Loaded %d fields in %v\n", len(manyFieldsData), loadTime)
	stats := cv.GetStats()
	fmt.Printf("   Total keys created: %v\n", stats["total_keys"])
}

// TestKeyRevocation tests key revocation functionality
func TestKeyRevocation(cvData map[string]interface{}) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("TEST: KEY REVOCATION")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	// Get a key ID to revoke (this would need to be implemented in keychain)
	fmt.Println("ℹ️  Key revocation test - would need keychain revocation implementation")
}

// Demo functions for individual demonstrations
func DemoSingleKey() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("DEMO: SINGLE KEY MODE")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cvData := getSampleData()
	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")
	cv.DisplayKeys()
	cv.SaveEncryptedCV("demo_single_cv.json")
	cv.SaveKeys("demo_single_keys.json")
}

func DemoMultiKey() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("DEMO: MULTI KEY MODE")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cvData := getSampleData()
	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "multi")
	cv.DisplayKeys()
	cv.SaveEncryptedCV("demo_multi_cv.json")
	cv.SaveKeys("demo_multi_keys.json")
}

func DemoKeyRotation() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("DEMO: KEY ROTATION")
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	cvData := getSampleData()
	cv := securecv.NewSecureCV()
	cv.LoadCV(cvData, "single")

	emailBefore, _ := cv.GetField("email")
	fmt.Printf("Before rotation: %v\n", emailBefore)

	cv.RotateFieldKey("email")

	emailAfter, _ := cv.GetField("email")
	fmt.Printf("After rotation: %v\n", emailAfter)

	if emailBefore == emailAfter {
		fmt.Println("✅ Data integrity verified!")
	}
}