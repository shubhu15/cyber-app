package main

import "net/http"

func (app *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/register", app.handleRegister)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/me", app.requireSession(app.handleMe))
	mux.HandleFunc("/session/refresh", app.requireSession(app.handleSessionRefresh))
	mux.HandleFunc("/uploads", app.requireSession(app.routeUploadsRoot))
	mux.HandleFunc("/uploads/", app.requireSession(app.routeUploadByID))
	return app.withCORS(mux)
}
