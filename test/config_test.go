package test

import (
	"os"
	"io/ioutil"
	"testing"

	"github-scanner/config"
)

func createTempEnv(t *testing.T) func() {
	// Create a temporary .env file in the current directory.
	err := ioutil.WriteFile(".env", []byte(""), 0644)
	if err != nil {
		t.Fatalf("failed to create .env file: %v", err)
	}
	// Return a cleanup function.
	return func() {
		_ = os.Remove(".env")
	}
}

func TestLoadConfig(t *testing.T) {
	cleanup := createTempEnv(t)
	defer cleanup()

	// This should succeed because .env exists.
	config.LoadConfig()
	dbPath := os.Getenv("DB_PATH")
	if dbPath != "./data.db" {
		t.Fatalf("Expected DB_PATH to be './data.db', got %s", dbPath)
	}
}
