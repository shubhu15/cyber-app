package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (app *application) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	var input registerRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: "Invalid JSON body."})
		return
	}

	email, password, err := normalizeCredentials(input.Email, input.Password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to secure password."})
		return
	}

	_, err = app.db.ExecContext(r.Context(), `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
	`, email, string(passwordHash))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSON(w, http.StatusConflict, messageResponse{Message: "User already exists."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to save user."})
		return
	}

	writeJSON(w, http.StatusCreated, messageResponse{Message: "Registration successful."})
}

func (app *application) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	email, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="simple-log-analyser"`)
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Missing Basic Auth credentials."})
		return
	}

	email, password, err := normalizeCredentials(email, password)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, messageResponse{Message: err.Error()})
		return
	}

	var user sessionUser
	var passwordHash string
	err = app.db.QueryRowContext(r.Context(), `
		SELECT id, email, password_hash
		FROM users
		WHERE email = $1
	`, email).Scan(&user.ID, &user.Email, &passwordHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid email or password."})
			return
		}
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to read user."})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Invalid email or password."})
		return
	}

	token, err := generateSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to create session."})
		return
	}

	if err := app.createSession(r.Context(), user.ID, token); err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to create session."})
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: app.sessionSameSite(),
		Secure:   app.sessionSecure(),
		Expires:  time.Now().Add(app.config.SessionTTL),
		MaxAge:   int(app.config.SessionTTL.Seconds()),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (app *application) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}

	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err == nil && strings.TrimSpace(cookie.Value) != "" {
		hash := hashSessionToken(cookie.Value)
		if _, deleteErr := app.db.ExecContext(r.Context(), `
			DELETE FROM sessions
			WHERE token_hash = $1
		`, hash); deleteErr != nil {
			log.Printf("delete session: %v", deleteErr)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: app.sessionSameSite(),
		Secure:   app.sessionSecure(),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (app *application) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	user := sessionUserFromContext(r.Context())
	writeJSON(w, http.StatusOK, meResponse{ID: user.ID, Email: user.Email})
}

func (app *application) handleSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, messageResponse{Message: "Method not allowed."})
		return
	}
	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "No session cookie."})
		return
	}
	hash := hashSessionToken(cookie.Value)
	newExpiry := time.Now().Add(app.config.SessionTTL)
	result, err := app.db.ExecContext(r.Context(), `
		UPDATE sessions SET expires_at = $2 WHERE token_hash = $1 AND expires_at > NOW()
	`, hash, newExpiry)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, messageResponse{Message: "Unable to refresh session."})
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Session expired or not found."})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     app.config.SessionCookieName,
		Value:    cookie.Value,
		Path:     "/",
		HttpOnly: true,
		SameSite: app.sessionSameSite(),
		Secure:   app.sessionSecure(),
		Expires:  newExpiry,
		MaxAge:   int(app.config.SessionTTL.Seconds()),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (app *application) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := app.authenticateRequest(r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, messageResponse{Message: "Authentication required."})
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, user)
		next(w, r.WithContext(ctx))
	}
}

func (app *application) authenticateRequest(r *http.Request) (*sessionUser, error) {
	cookie, err := r.Cookie(app.config.SessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return nil, errors.New("missing session")
	}

	hash := hashSessionToken(cookie.Value)
	var user sessionUser
	err = app.db.QueryRowContext(r.Context(), `
		SELECT users.id, users.email
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token_hash = $1
		  AND sessions.expires_at > NOW()
	`, hash).Scan(&user.ID, &user.Email)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (app *application) createSession(ctx context.Context, userID int64, token string) error {
	hash := hashSessionToken(token)
	_, err := app.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, hash, time.Now().Add(app.config.SessionTTL))
	return err
}

// sessionSameSite picks the right cookie SameSite policy for the environment.
// Production runs the frontend and API on different domains (e.g. Vercel +
// Render), which requires SameSite=None;Secure for the browser to send the
// session cookie at all. Locally we keep Lax so the cookie still works on
// http:// without the Secure flag.
func (app *application) sessionSameSite() http.SameSite {
	if app.config.AppEnv == "production" {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

// sessionSecure mirrors sessionSameSite: SameSite=None requires Secure=true,
// and we never want Secure on plain http:// dev.
func (app *application) sessionSecure() bool {
	return app.config.AppEnv == "production"
}

func normalizeCredentials(email, password string) (string, string, error) {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	if cleanEmail == "" {
		return "", "", errors.New("Email is required.")
	}
	if !strings.Contains(cleanEmail, "@") {
		return "", "", errors.New("Enter a valid email address.")
	}
	if password == "" {
		return "", "", errors.New("Password is required.")
	}
	return cleanEmail, password, nil
}

func generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func sessionUserFromContext(ctx context.Context) sessionUser {
	user, _ := ctx.Value(userContextKey).(*sessionUser)
	if user == nil {
		return sessionUser{}
	}
	return *user
}
