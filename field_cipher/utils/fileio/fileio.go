package fileio

import (
	"encoding/json"
	"fmt"
	"os"
)

// SaveJSON saves data as JSON to file
func SaveJSON(filename string, data interface{}) error {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %v", filename, err)
	}

	fmt.Printf("Saved data to %s\n", filename)
	return nil
}

// LoadJSON loads JSON data from file
func LoadJSON(filename string, result interface{}) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("failed to parse JSON from %s: %v", filename, err)
	}

	fmt.Printf("Loaded data from %s\n", filename)
	return nil
}

// FileExists checks if a file exists
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// CreateBackup creates a backup of a file
func CreateBackup(filename string) error {
	if !FileExists(filename) {
		return fmt.Errorf("file %s does not exist", filename)
	}

	backupName := filename + ".backup"
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return os.WriteFile(backupName, data, 0644)
}

// LoadCVData loads CV data from JSON file
func LoadCVData(filename string) (map[string]interface{}, error) {
	var cvData map[string]interface{}
	if err := LoadJSON(filename, &cvData); err != nil {
		return nil, err
	}
	return cvData, nil
}

// EnsureDirectory ensures a directory exists
func EnsureDirectory(dirname string) error {
	return os.MkdirAll(dirname, 0755)
}

// ListFiles lists all files in a directory with a specific extension
func ListFiles(dirname, extension string) ([]string, error) {
	files, err := os.ReadDir(dirname)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, file := range files {
		if !file.IsDir() {
			name := file.Name()
			if extension == "" || (len(name) > len(extension) && name[len(name)-len(extension):] == extension) {
				result = append(result, name)
			}
		}
	}

	return result, nil
}