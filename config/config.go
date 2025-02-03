package config

import (
	"log"
	"os"
)

func LoadConfig() {
	if _, err := os.Stat(".env"); err == nil {
		err := os.Setenv("DB_PATH", "./data.db")
		if err != nil {
			log.Fatal("Error setting environment variables")
		}
	} else {
		log.Fatal(".env file not found")
	}
}
