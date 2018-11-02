package server

import (
	"fmt"
	"net"
	"net/http"
	"os"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/handlers"
	"github.com/makkes/mux"
	"github.com/makkes/services.makk.es/auth/business"
	"github.com/makkes/services.makk.es/auth/mailer"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/persistence/dynamodb"
	"github.com/makkes/services.makk.es/auth/persistence/inmemorydb"
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

func NewServer(baseURL string) *Server {
	router := mux.NewRouter()
	dynamodbTable := os.Getenv("DYNAMODB_TABLE")
	if dynamodbTable == "" {
		dynamodbTable = "auth"
	}
	dbTypes := map[string]func() (persistence.DB, error){
		"dynamodb": func() (persistence.DB, error) {
			return dynamodb.NewDynamoDB(dynamodbTable)
		},
		"inmemory": func() (persistence.DB, error) {
			return inmemorydb.NewInMemoryDB()
		},
	}

	dbType := os.Getenv("DB_TYPE")
	if dbType == "" {
		dbType = "dynamodb"
	}
	newDB := dbTypes[dbType]
	if newDB == nil {
		panic(fmt.Sprintf("'%s' is not a valid database type", dbType))
	}
	db, err := newDB()
	if err != nil {
		panic(fmt.Sprintf("Could not create db: %s", err))
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
		utils.PreloadApps(s.db, preloadAppsFile)
	}

	listener, err := net.Listen("tcp", listenHost+":"+listenPort)
	if err != nil {
		return fmt.Errorf("Error starting HTTP server %s", err)
	}
	log.Info("Auth Service %s listening on %s:%s serving %s\n", version, listenHost, listenPort, s.baseURL)
	s.srv = &http.Server{Handler: handlers.LoggingHandler(os.Stdout, s.router)}
	err = s.srv.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("%s", err)
	}
	return nil
}

func (s *Server) Stop() {
	s.srv.Shutdown(nil)

}
