// Command console-backend is the AriGuard Console backend: agent ingest, a
// metrics scraper and the read API, in a single binary backed by SQLite.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/CosminMilica/ariguard/console/backend/api"
	"github.com/CosminMilica/ariguard/console/backend/ingest"
	"github.com/CosminMilica/ariguard/console/backend/scrape"
	"github.com/CosminMilica/ariguard/console/backend/store"
)

func main() {
	dbPath := flag.String("db", "./ariguard-console.db", "SQLite database file")
	addr := flag.String("addr", ":8080", "HTTP listen address")
	authToken := flag.String("auth-token", os.Getenv("ARIGUARD_TOKEN"),
		"shared bearer token required on the /api/v1 control-plane endpoints (empty = disabled)")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go scrape.New(db).Run(ctx)

	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	if _, err := os.Stat("public/index.html"); err == nil {
		mux.Handle("/", http.FileServer(http.Dir("public")))
		log.Printf("serving static frontend from ./public")
	}

	if *authToken == "" {
		log.Printf("WARNING: no --auth-token set; the /api/v1 control-plane endpoints are unauthenticated")
	} else {
		log.Printf("control-plane auth enabled on %s*", ingest.AuthPrefix)
	}
	srv := &http.Server{Addr: *addr, Handler: api.CORS(ingest.Auth(*authToken, mux))}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	log.Printf("console backend listening on %s (db %s)", *addr, *dbPath)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
