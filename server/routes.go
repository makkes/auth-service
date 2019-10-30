package server

import (
	"bytes"
	"html/template"
	"net/http"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/handlers"
	"github.com/makkes/services.makk.es/auth/server/middleware"
)

const versionPageTmpl = `<!DOCTYPE html>
<html>
	<head>
		<title>Auth Service {{.}}</title>
	</head>
	<body>
		<a href="https://github.com/makkes-services/auth-service/commit/{{.}}">{{.}}</a>
	</body>
</html>
`

func handleVersion(v string) func(http.ResponseWriter, *http.Request) {
	tmpl := template.Must(template.New("version").Parse(versionPageTmpl))
	var pageBytes bytes.Buffer
	err := tmpl.Execute(&pageBytes, v)
	if err != nil {
		panic(err)
	}
	page := pageBytes.Bytes()
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, writeErr := w.Write(page)
		if writeErr != nil {
			log.Info("Error sending body: %v", writeErr)
		}
	}
}

func (s *Server) routes() {
	appID := middleware.ApplicationID(s.db)

	// these routes are only available to authenticated users (providing a JWT in the 'Authorization' header)
	authenticatedRoutes := s.router.NewRoute().Subrouter()
	authenticatedRoutes.Use(appID)
	authenticatedRoutes.Use(middleware.Authenticate(s.db, true))
	authenticatedRoutes.HandleFunc("/account", http.HandlerFunc(s.handlers.GetCurrentAccountHandler)).Methods("GET")
	authenticatedRoutes.HandleFunc("/accounts", http.HandlerFunc(s.handlers.GetAccountsHandler)).Methods("GET")
	authenticatedRoutes.HandleFunc("/accounts/{id}", s.handlers.GetAccountHandler).Methods("GET")
	authenticatedRoutes.HandleFunc("/accounts/{id}", s.handlers.DeleteAccountHandler).Methods("DELETE")
	authenticatedRoutes.HandleFunc("/accounts/{id}/roles", s.handlers.GetRolesHandler).Methods("GET")
	authenticatedRoutes.HandleFunc("/apps", s.handlers.CreateApp).Methods("POST")
	authenticatedRoutes.HandleFunc("/apps", s.handlers.GetApps).Methods("GET")
	authenticatedRoutes.HandleFunc("/apps/{id}", s.handlers.GetAppHandler).Methods("GET")
	authenticatedRoutes.HandleFunc("/apps/{id}", s.handlers.DeleteAppHandler).Methods("DELETE")
	authenticatedRoutes.Handle("/apps/{id}/name", handlers.ContentTypeHandler(http.HandlerFunc(s.handlers.UpdateAppNameHandler), "text/plain")).Methods("PUT")
	authenticatedRoutes.Handle("/apps/{id}/origin", handlers.ContentTypeHandler(http.HandlerFunc(s.handlers.UpdateAppOriginHandler), "text/plain")).Methods("PUT")

	// these routes are available to anonymous users
	openRoutes := s.router.NewRoute().Subrouter()
	openRoutes.Use(appID)
	openRoutes.Handle("/accounts/{id}/active", http.HandlerFunc(s.handlers.ActivateHandler)).Methods("PUT")
	openRoutes.Handle("/accounts", handlers.ContentTypeHandler(http.HandlerFunc(s.handlers.CreateAccountHandler), "application/json")).Methods("POST")
	openRoutes.HandleFunc("/tokens", s.handlers.CreateTokenHandler).Methods("POST").HeadersRegexp("content-type", "^application/x-www-form-urlencoded(; *charset=.*)*$")

	// this router is a special-purpose one only used for refreshing an existing, but expired JWT
	halfAuthenticatedRoutes := s.router.NewRoute().Subrouter()
	halfAuthenticatedRoutes.Use(middleware.Authenticate(s.db, false))
	halfAuthenticatedRoutes.HandleFunc("/tokens", s.handlers.RefreshTokenHandler).Methods("POST").Headers("content-type", "^application/jwt(; *charset=.*)*$")

	s.router.HandleFunc("/version", handleVersion(s.version)).Methods("GET")

	s.router.PathPrefix("/").Methods("OPTIONS")
	corsHandler := handlers.CORS(handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT"}), handlers.AllowedOrigins(middleware.AllowedOrigins(s.db)), handlers.AllowedHeaders([]string{"Authorization", "X-Activation-Token", "Content-Type", "X-Application-ID"}))
	s.router.Use(corsHandler)
}
