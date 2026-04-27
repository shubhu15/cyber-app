package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const defaultDatabasePath = "./users.db"

type server struct {
	db *sql.DB
}

type credentialsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

func main() {
	databasePath := os.Getenv("DATABASE_PATH")
	if strings.TrimSpace(databasePath) == "" {
		databasePath = defaultDatabasePath
	}

	db, err := sql.Open("sqlite3", databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		log.Fatalf("initialize database: %v", err)
	}

	app := &server{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("/register", app.handleRegister)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/health", handleHealth)

	addr := ":8080"
	log.Printf("backend listening on %s", addr)
	if err := http.ListenAndServe(addr, withCORS(mux)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func initializeDatabase(db *sql.DB) error {
	const schema = `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`

	_, err := db.Exec(schema)
	return err
}

func (s *server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	var input credentialsRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid JSON body."})
		return
	}

	username, password, err := normalizeCredentials(input.Username, input.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to secure password."})
		return
	}

	_, err = s.db.Exec(
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username,
		string(passwordHash),
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, messageResponse{Message: "User already exists."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to save user."})
		return
	}

	writeJSON(w, http.StatusCreated, messageResponse{Message: "Registration successful."})
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="simple-log-analyser"`)
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Missing Basic Auth credentials."})
		return
	}

	username, password, err := normalizeCredentials(username, password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	var passwordHash string
	err = s.db.QueryRow(
		`SELECT password_hash FROM users WHERE username = ?`,
		username,
	).Scan(&passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid username or password."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read user."})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid username or password."})
		return
	}

	writeJSON(w, http.StatusOK, messageResponse{Message: "Login successful."})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	writeJSON(w, http.StatusOK, messageResponse{Message: "Backend is healthy."})
}

func normalizeCredentials(username, password string) (string, string, error) {
	cleanUsername := strings.TrimSpace(username)
	if cleanUsername == "" {
		return "", "", errors.New("Username is required.")
	}
	if password == "" {
		return "", "", errors.New("Password is required.")
	}
	return cleanUsername, password, nil
}

func writeJSON(w http.ResponseWriter, status int, payload messageResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func withCORS(next http.Handler) http.Handler {
	allowedOrigins := map[string]struct{}{
		"http://localhost:5173": {},
		"http://127.0.0.1:5173": {},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
