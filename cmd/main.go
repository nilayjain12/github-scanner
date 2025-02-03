package main

import (
	"fmt"
	"log"
	"net/http"

	"github-scanner/api"
	"github-scanner/config"
	"github-scanner/internal/database"

	"github.com/gorilla/mux"
)

func main() {
	config.LoadConfig()
	database.InitDB()

	r := mux.NewRouter()
	r.HandleFunc("/scan", api.ScanHandler).Methods("POST")
	r.HandleFunc("/query", api.QueryHandler).Methods("POST")

	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
