// config.go
package config

import (
	"log"
	"os"
)

// LoadConfig loads environment configuration from .env file.
func LoadConfig() {
	if _, err := os.Stat(".env"); err == nil {
		if err := os.Setenv("DB_PATH", "./data.db"); err != nil {
			log.Fatalf("ERROR: Failed to set DB_PATH environment variable: %v", err)
		}
		log.Println("INFO: Environment variables loaded from .env")
	} else {
		log.Fatal("ERROR: .env file not found")
	}
}
