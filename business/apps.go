package business

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/gofrs/uuid"
)

type AppName struct {
	Name string
}

func (appName AppName) Validate() ValidationResult {
	vr := ValidationResult{
		Errors: make(map[string]string),
	}
	appName.Name = strings.TrimSpace(appName.Name)
	if appName.Name == "" {
		vr.Errors["name"] = "May not be empty"
	}

	return vr
}

type AppOrigin struct {
	Origin string
}

func (appOrigin AppOrigin) Validate() ValidationResult {
	vr := ValidationResult{
		Errors: make(map[string]string),
	}
	appOrigin.Origin = strings.TrimSpace(appOrigin.Origin)
	if appOrigin.Origin == "" {
		vr.Errors["origin"] = "May not be empty"
	}

	return vr
}

type AppCreation struct {
	Name          string
	MaxAccounts   int
	AllowedOrigin string
}

func (ac AppCreation) Validate() ValidationResult {
	vr := ValidationResult{
		Errors: make(map[string]string),
	}
	ac.Name = strings.TrimSpace(ac.Name)
	if ac.Name == "" {
		vr.Errors["name"] = "May not be empty"
	}

	ac.AllowedOrigin = strings.TrimSpace(ac.AllowedOrigin)
	if ac.AllowedOrigin == "" {
		vr.Errors["allowedOrigin"] = "May not be empty"
	}
	if ac.MaxAccounts <= 0 {
		vr.Errors["maxAccounts"] = "Must be greater than 0"
	}

	return vr
}

var ErrReproductionDenied = errors.New("This app is not allowed to create more apps")
var ErrAppDoesNotExist = errors.New("The requested app does not exist")
var ErrAppUpdateForbidden = errors.New("App update forbidden")

type AppService struct {
	db persistence.DB
}

func NewAppService(db persistence.DB) *AppService {
	return &AppService{
		db: db,
	}
}

type AuthCtx struct {
	svc  AppService
	auth Authentication
}

func (s AppService) NewAuthCtx(auth Authentication) AuthCtx {
	return AuthCtx{
		svc:  s,
		auth: auth,
	}
}

func (ctx AuthCtx) CreateApp(newApp AppCreation, admins []persistence.AccountID) (*persistence.App, error) {
	if ctx.auth.App.ID.ID != "0a791409-d58d-4175-ba02-2bdbdb8e6629" {
		return nil, ErrReproductionDenied
	}
	appID, err := uuid.NewV4()
	if err != nil {
		log.Error("Could not create UUID for new app: %s", err)
		return nil, err
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error("Could not generate private key for JWT use: %s", err)
		return nil, err
	}
	createdApp, err := ctx.svc.db.SaveApp(persistence.AppID{appID.String()}, newApp.Name, newApp.MaxAccounts, newApp.AllowedOrigin, persistence.MailTemplates{}, admins, *privKey)
	if err != nil {
		log.Error("Received unknown error when creating app %#v: %s", newApp, err)
		return nil, fmt.Errorf("App could not created")
	}
	return createdApp, nil
}

func (ctx AuthCtx) DeleteApp(appID persistence.AppID) error {
	app := ctx.svc.db.GetApp(appID)
	if app == nil {
		return ErrAppDoesNotExist
	}
	for _, adminID := range app.Admins {
		if adminID == ctx.auth.Account.ID {
			return ctx.svc.db.DeleteApp(appID)
		}
	}
	return ErrAppUpdateForbidden
}

func (ctx AuthCtx) UpdateAppName(appID persistence.AppID, newName AppName) error {
	app := ctx.svc.db.GetApp(appID)
	if app == nil {
		return ErrAppDoesNotExist
	}
	for _, adminID := range app.Admins {
		if adminID == ctx.auth.Account.ID {
			return ctx.svc.db.App(appID).UpdateAppName(newName.Name)
		}
	}
	return ErrAppUpdateForbidden
}

func (ctx AuthCtx) UpdateAppOrigin(appID persistence.AppID, newOrigin AppOrigin) error {
	app := ctx.svc.db.GetApp(appID)
	if app == nil {
		return ErrAppDoesNotExist
	}
	for _, adminID := range app.Admins {
		if adminID == ctx.auth.Account.ID {
			return ctx.svc.db.App(appID).UpdateAppOrigin(newOrigin.Origin)
		}
	}
	return ErrAppUpdateForbidden
}

func (ctx AuthCtx) GetApps() []*persistence.App {
	if ctx.auth.App.ID.ID == "0a791409-d58d-4175-ba02-2bdbdb8e6629" {
		if ctx.auth.Account.HasRole("admin") {
			return ctx.svc.db.GetApps()
		}
		res := make([]*persistence.App, 0)
		for _, app := range ctx.svc.db.GetApps() {
			for _, adminID := range app.Admins {
				if adminID == ctx.auth.Account.ID {
					res = append(res, app)
				}
			}
		}
		return res
	} else if ctx.auth.Account.HasRole("admin") {
		return []*persistence.App{&ctx.auth.App}
	}

	return []*persistence.App{}
}

func (s *AppService) GetApp(ctxApp persistence.AppID, authID persistence.AccountID, appID persistence.AppID) *persistence.App {
	log.Info("Returning app info for %s to %s", appID, authID)
	account := s.db.App(ctxApp).GetAccount(authID)
	if account != nil && (account.HasRole("admin") && ctxApp == appID || ctxApp.ID == "0a791409-d58d-4175-ba02-2bdbdb8e6629") {
		return s.db.GetApp(appID)
	}
	return nil
}
