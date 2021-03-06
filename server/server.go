package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"golang.org/x/xerrors"

	"github.com/makkes/services.makk.es/auth/persistence/postgres"

	"github.com/gorilla/mux"
	log "github.com/makkes/golib/logging"
	"github.com/makkes/handlers"
	"github.com/makkes/services.makk.es/auth/business"
	"github.com/makkes/services.makk.es/auth/mailer"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/utils"
)

var version string

type Server struct {
	baseURL         string
	srv             *http.Server
	db              persistence.DB
	router          *mux.Router
	mailer          mailer.Mailer
	accountsService *business.AccountService
	appService      *business.AppService
	handlers        *Handlers
	version         string
}

func getEnvOrDefault(envName, defaultVal string) string {
	res := os.Getenv(envName)
	if res == "" {
		return defaultVal
	}
	return res
}

func NewServer(baseURL string) *Server {
	router := mux.NewRouter()

	user := getEnvOrDefault("POSTGRES_USER", "auth")
	password := getEnvOrDefault("POSTGRES_PASSWORD", "auth")
	dbName := getEnvOrDefault("POSTGRES_DB_NAME", "auth")
	host := getEnvOrDefault("POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("POSTGRES_PORT", "5432")
	sslMode := getEnvOrDefault("POSTGRES_SSL_MODE", "disable")
	db, err := postgres.NewPostgresDB(user, password, dbName, host, port, sslMode)
	if err != nil {
		panic(fmt.Sprintf("Could not create db: %s", err.Error()))
	}

	mailHost := os.Getenv("MAIL_HOST")
	mailPort := os.Getenv("MAIL_PORT")
	mailUsername := os.Getenv("MAIL_USERNAME")
	mailPassword := os.Getenv("MAIL_PASSWORD")
	mailer := mailer.NewSMTPMailer(mailHost, mailPort, mailUsername, mailPassword)
	as := business.NewAccountService(db, mailer)
	appService := business.NewAppService(db)
	hndlrs := newHandlers(as, appService, baseURL)

	return &Server{
		baseURL:         baseURL,
		db:              db,
		router:          router,
		mailer:          mailer,
		accountsService: as,
		appService:      appService,
		handlers:        hndlrs,
		version:         version,
	}
}

func (s *Server) Start(listenHost, listenPort string) error {
	s.routes()
	preloadAppsFile := os.Getenv("PRELOAD_APPS_FILE")
	if preloadAppsFile != "" {
		err := utils.PreloadApps(s.db, preloadAppsFile)
		if err != nil {
			return xerrors.Errorf("could not preload apps: %w", err)
		}
	}

	listener, err := net.Listen("tcp", listenHost+":"+listenPort)
	if err != nil {
		return fmt.Errorf("Error starting HTTP server %s", err)
	}
	log.Info("Auth Service %s listening on %s:%s serving %s\n", version, listenHost, listenPort, s.baseURL)
	s.srv = &http.Server{Handler: handlers.CombinedLoggingHandler(os.Stdout, s.router)}
	err = s.srv.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("%s", err)
	}
	return nil
}

func (s *Server) Stop() {
	err := s.srv.Shutdown(context.Background())
	if err != nil {
		log.Error("Error shutting server down: %v", err)
	}

}
