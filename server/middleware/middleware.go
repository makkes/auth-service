package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/business"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/utils"
)

type key int

const AuthContextKey key = 0
const AppIDContextKey key = 1

func extractAppFromRequest(r *http.Request, db persistence.DB) *persistence.App {
	app := r.Context().Value(AppIDContextKey)
	if app != nil {
		return app.(*persistence.App)
	}
	appID := r.Header.Get("X-Application-ID")
	if appID == "" {
		log.Info("Received request without X-Application-ID")
		return nil
	}
	return db.GetApp(persistence.AppID{ID: appID})
}

type accept struct {
	h          http.Handler
	mediaTypes []utils.MediaType
}

func Accept(mediaTypes []utils.MediaType) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		a := accept{
			h:          h,
			mediaTypes: mediaTypes,
		}
		return a
	}
}

func (a accept) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	acceptedTypes, err := utils.ParseAcceptHeader(r.Header.Get("Accept"))
	if err != nil {
		log.Info("Error checking Accept header '%s': %s", r.Header.Get("Accept"), err)
	}
	for _, acceptable := range a.mediaTypes {
		for _, accepted := range acceptedTypes {
			if acceptable.Matches(accepted) {
				a.h.ServeHTTP(w, r)
				return
			}
		}
	}
	w.WriteHeader(http.StatusNotAcceptable)
}

func AllowedOrigins(db persistence.DB) func(*http.Request) ([]string, *http.Request) {
	return func(r *http.Request) ([]string, *http.Request) {
		app := extractAppFromRequest(r, db)
		if app == nil {
			if r.Method == "OPTIONS" {
				log.Info("Received pre-flight request, allowing any origin")
				return []string{"*"}, r
			} else {
				log.Warn("Sending empty allowed origins for %s", r.Header.Get("Origin"))
				return []string{""}, r
			}
		}
		log.Info("Returning origin %s for %s", app.AllowedOrigin, app.ID)
		return []string{app.AllowedOrigin}, r.WithContext(context.WithValue(r.Context(), AppIDContextKey, app))
	}
}

type applicationID struct {
	h  http.Handler
	db persistence.DB
}

func ApplicationID(db persistence.DB) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		aih := applicationID{
			h,
			db,
		}
		return aih
	}
}

func (aih applicationID) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	app := extractAppFromRequest(r, aih.db)
	if app == nil {
		log.Warn("Denying request with unknown app ID from %s (X-Application-ID is %s)", r.Header.Get("Origin"), r.Header.Get("X-Application-ID"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aih.h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AppIDContextKey, app)))
}

type authMiddleware struct {
	h                    http.Handler
	db                   persistence.DB
	checkTokenExpiration bool
}

func Authenticate(db persistence.DB, checkTokenExpiration bool) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		auth := authMiddleware{
			h:                    h,
			db:                   db,
			checkTokenExpiration: checkTokenExpiration,
		}
		return auth
	}
}

func (auth authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(authHeader) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if authHeader[0] != "Bearer" {
		log.Info("Denying access: bearer token missing")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	app := extractAppFromRequest(r, auth.db)
	claims, err := utils.ParseJWT(authHeader[1], app.PrivateKey.Key.Public(), auth.checkTokenExpiration, time.Now())
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			if claims != nil {
				expiredSinceSeconds := time.Since(time.Unix(claims.ExpiresAt, 0)) / time.Second
				log.Info("Denying access, token is expired since %d seconds", expiredSinceSeconds)
			}
		} else {
			log.Info("Denying access: %s", err)
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	accountID, err := persistence.NewAccountID(claims.Subject)
	if err != nil {
		log.Info("Could not create AccountID from '%s': %s", claims.Subject, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	appID, err := persistence.NewAppID(claims.Issuer)
	if err != nil {
		log.Info("Could not create AppID from '%s': %s", claims.Issuer, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if appID != app.ID {
		log.Info("JWT app ID (%s) and HTTP header app ID (%s) differ; denying request", appID, app.ID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	account := auth.db.App(appID).GetAccount(accountID)
	if account == nil {
		log.Info("Denying access: JWT contains invalid account ID %s", accountID)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	authentication := business.Authentication{Account: *account, App: *app, TokenClaims: *claims}
	log.Info("Authenticated user: %s, %s", authentication.Account.Email, authentication.App.Name)
	auth.h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthContextKey, authentication)))
}
