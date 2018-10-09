package server

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"

	log "github.com/makkes/justlib/logging"
	"github.com/makkes/mux"
	"github.com/makkes/services.makk.es/auth/business"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/server/middleware"
	"github.com/makkes/services.makk.es/auth/utils"
)

type Handlers struct {
	accountService *business.AccountService
	appService     *business.AppService
	baseURL        string
}

func newHandlers(accountService *business.AccountService, appService *business.AppService, baseURL string) *Handlers {
	return &Handlers{
		accountService: accountService,
		appService:     appService,
		baseURL:        baseURL,
	}
}

func (h *Handlers) GetRolesHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	//accountID, err := NewAccountID(mux.Vars(r)["id"])
	//if err != nil {
	//w.WriteHeader(http.StatusNotFound)
	//return
	//}
	//r.Context().Value(UserContextKey)
}

func (h *Handlers) CreateApp(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	authID := auth.Account.ID
	appID := auth.App.ID
	log.Info("Creating app from %s", appID)

	var newApp business.AppCreation
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&newApp)
	if err != nil {
		log.Info("Error unmarshaling body: %s", err)
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, err.Error())
		return
	}
	valRes := newApp.Validate()
	if valRes.HasErrors() {
		utils.ReplyJSON(w, http.StatusUnprocessableEntity, valRes.Errors, nil)
		return
	}

	createdApp, err := h.appService.NewAuthCtx(auth).CreateApp(newApp, []persistence.AccountID{authID})
	if err != nil {
		log.Info("Error creating app: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "An unknown server error occurred")
		return
	}
	utils.ReplyJSON(w, http.StatusCreated, createdApp, map[string]string{
		"Location": h.baseURL + "/apps/" + createdApp.ID.String(),
	})
}

func (h *Handlers) UpdateAppOriginHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	ctxAppID := auth.App.ID
	appID, err := persistence.NewAppID(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	log.Info("Updating app origin %s from %s", appID, ctxAppID)

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, err.Error())
		return
	}
	newOrigin := business.AppOrigin{
		Origin: string(bodyBytes),
	}
	valRes := newOrigin.Validate()
	if valRes.HasErrors() {
		utils.ReplyJSON(w, http.StatusUnprocessableEntity, valRes.Errors, nil)
		return
	}

	err = h.appService.NewAuthCtx(auth).UpdateAppOrigin(appID, newOrigin)
	if err != nil {
		switch err {
		case business.ErrAppDoesNotExist:
			w.WriteHeader(http.StatusNotFound)
		case business.ErrAppUpdateForbidden:
			w.WriteHeader(http.StatusForbidden)
		default:
			log.Info("Error updating app origin %s to %s: %s", appID, newOrigin, err)
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "An unknown server error occurred")
		}
		return
	}
	w.Header().Set("Content-Location", h.baseURL+"/apps/"+appID.String())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) UpdateAppNameHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	ctxAppID := auth.App.ID
	appID, err := persistence.NewAppID(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	log.Info("Updating app name %s from %s", appID, ctxAppID)

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, err.Error())
		return
	}
	newName := business.AppName{
		Name: string(bodyBytes),
	}
	valRes := newName.Validate()
	if valRes.HasErrors() {
		utils.ReplyJSON(w, http.StatusUnprocessableEntity, valRes.Errors, nil)
		return
	}

	err = h.appService.NewAuthCtx(auth).UpdateAppName(appID, newName)
	if err != nil {
		switch err {
		case business.ErrAppDoesNotExist:
			w.WriteHeader(http.StatusNotFound)
		case business.ErrAppUpdateForbidden:
			w.WriteHeader(http.StatusForbidden)
		default:
			log.Info("Error updating app name %s to %s: %s", appID, newName, err)
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "An unknown server error occurred")
		}
		return
	}
	w.Header().Set("Content-Location", h.baseURL+"/apps/"+appID.String())
	w.WriteHeader(http.StatusNoContent)

}

func (h *Handlers) GetApps(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	apps := h.appService.NewAuthCtx(auth).GetApps()
	if apps == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	utils.WriteAppsAsCollectionJSON(w, h.baseURL, apps)
}

func (h *Handlers) GetAppHandler(w http.ResponseWriter, r *http.Request) {
	appID, err := persistence.NewAppID(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	app := h.appService.GetApp(auth.App.ID, auth.Account.ID, appID)
	if app == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	utils.ReplyJSON(w, http.StatusOK, app, nil)
}

func (h *Handlers) CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	if email == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	app := r.Context().Value(middleware.AppIDContextKey).(*persistence.App)
	token, err := h.accountService.CreateAuthenticationToken(&app.PrivateKey.Key, app.ID, email, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(token))
}

func (h *Handlers) ActivateHandler(w http.ResponseWriter, r *http.Request) {
	activationToken := r.Header.Get("X-Activation-Token")
	if activationToken == "" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	accountID, err := persistence.NewAccountID(mux.Vars(r)["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	app := r.Context().Value(middleware.AppIDContextKey).(*persistence.App)
	err = h.accountService.ActivateAccount(app.ID, activationToken, accountID)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Add("Location", h.baseURL+"/accounts/"+accountID.String())
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) GetAccountHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	accountID, err := persistence.NewAccountID(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	account := h.accountService.GetAccount(auth.App.ID, auth.Account.ID, accountID)
	if account == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	utils.ReplyJSON(w, http.StatusOK, account, nil)
}

func (h *Handlers) GetCurrentAccountHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	account := h.accountService.GetAccount(auth.App.ID, auth.Account.ID, auth.Account.ID)
	if account == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	utils.ReplyJSON(w, http.StatusOK, account, nil)
}

func (h *Handlers) GetAccountsHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Context().Value(middleware.AuthContextKey).(business.Authentication)
	account := h.accountService.GetAccounts(auth.App.ID, auth.Account.ID)
	if account == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	utils.WriteAccountsAsCollectionJSON(w, h.baseURL, account)
}

func (h *Handlers) CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
	app := r.Context().Value(middleware.AppIDContextKey).(*persistence.App)
	var user business.AccountCreation
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&user)
	if err != nil {
		log.Info("Error unmarshaling body: %s", err)
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, err.Error())
		return
	}

	valRes := user.Validate()

	if valRes.HasErrors() {
		utils.ReplyJSON(w, http.StatusUnprocessableEntity, valRes.Errors, nil)
		return
	}

	user.Roles = nil
	newUser, err := h.accountService.NewAppContext(app).CreateAccount(user)
	if err != nil {
		if err == business.EmailExistsError {
			utils.ReplyJSON(w, http.StatusUnprocessableEntity, map[string]string{"email": "This e-mail address is already associated with an existing account"}, nil)
			return
		}
		if err == business.AppQuotaExceeded {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Location", h.baseURL+"/accounts/"+newUser.ID.String())
	w.WriteHeader(http.StatusCreated)
}
