package main

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	cfg := loadConfig()
	mode := cfg.Mode
	if len(os.Args) > 1 && os.Args[1] != "" {
		mode = os.Args[1]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := db.PingContext(pingCtx); err != nil {
		cancel()
		log.Fatalf("ping database: %v", err)
	}
	cancel()

	if err := initializeDatabase(ctx, db); err != nil {
		log.Fatalf("initialize database: %v", err)
	}

	storage := newLocalDiskStorage(cfg.UploadDir)
	app := &application{
		config:  cfg,
		db:      db,
		storage: storage,
	}

	switch mode {
	case "worker":
		log.Printf("worker started with poll interval %s", cfg.WorkerPollInterval)
		if err := app.runWorker(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("worker stopped: %v", err)
		}
	default:
		server := &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           app.routes(),
			ReadHeaderTimeout: 5 * time.Second,
		}

		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		}()

		log.Printf("api listening on %s", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}
}
