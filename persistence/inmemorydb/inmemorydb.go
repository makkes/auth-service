package inmemorydb

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	log "github.com/makkes/justlib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
)

type InMemoryDB struct {
	apps             map[persistence.AppID]*persistence.App
	accounts         map[persistence.AppID]map[persistence.AccountID]*persistence.Account
	activationTokens map[string]*persistence.AccountID
}

type InMemoryAppContext struct {
	db    *InMemoryDB
	appID persistence.AppID
}

func (ctx *InMemoryAppContext) GetAccountByEmail(email string) *persistence.Account {
	accounts := ctx.db.accounts[ctx.appID]
	for _, account := range accounts {
		if account.Email == email {
			return account
		}
	}
	return nil
}

func (ctx *InMemoryAppContext) SaveAccount(account persistence.Account) {
	if ctx.db.accounts[ctx.appID] == nil {
		ctx.db.accounts[ctx.appID] = make(map[persistence.AccountID]*persistence.Account)
	}
	ctx.db.accounts[ctx.appID][account.ID] = &account
	log.Info("%s", ctx.db)
}

func (ctx *InMemoryAppContext) GetAccount(id persistence.AccountID) *persistence.Account {
	return ctx.db.accounts[ctx.appID][id]
}

func (ctx *InMemoryAppContext) GetAccounts() []*persistence.Account {
	accounts := ctx.db.accounts[ctx.appID]
	res := []*persistence.Account{}
	for _, v := range accounts {
		res = append(res, v)
	}
	return res
}

func (ctx *InMemoryAppContext) GetActivationToken(id persistence.AccountID) string {
	for token, accountID := range ctx.db.activationTokens {
		if *accountID == id {
			return token
		}
	}
	return ""
}

func NewInMemoryDB() (*InMemoryDB, error) {
	db := &InMemoryDB{
		accounts:         make(map[persistence.AppID]map[persistence.AccountID]*persistence.Account),
		activationTokens: make(map[string]*persistence.AccountID),
		apps:             make(map[persistence.AppID]*persistence.App),
	}
	return db, nil
}

func (db *InMemoryDB) String() string {
	var dbString strings.Builder
	dbString.WriteString("\naccounts:\n")
	for appID, app := range db.apps {
		dbString.WriteString(fmt.Sprintf("\tid:%s maxAccounts:%d allowedOrigin:%s admins:%s\n", appID, app.MaxAccounts, app.AllowedOrigin, app.Admins))
		for _, acc := range db.accounts[appID] {
			dbString.WriteString(fmt.Sprintf("\t\t%s\n", acc.String()))
		}
	}
	return dbString.String()
}

func (ctx *InMemoryAppContext) SaveActivationToken(accountID persistence.AccountID, token string) error {
	ctx.db.activationTokens[token] = &accountID
	log.Info("%s", ctx.db)
	return nil
}

func (ctx *InMemoryAppContext) DeleteActivationToken(id persistence.AccountID) error {
	for token, aid := range ctx.db.activationTokens {
		if *aid == id {
			delete(ctx.db.activationTokens, token)
		}
	}
	log.Info("%s", ctx.db)
	return nil
}

func (ctx *InMemoryAppContext) UpdateAppName(newName string) error {
	return nil
}

func (ctx *InMemoryAppContext) UpdateAppOrigin(newOrigin string) error {
	return nil
}

func (db *InMemoryDB) SaveApp(appID persistence.AppID, name string, maxAccounts int, allowedOrigin string, mailTemplates persistence.MailTemplates, admins []persistence.AccountID, privateKey rsa.PrivateKey) (*persistence.App, error) {
	if db.apps[appID] != nil {
		return nil, errors.New("Duplicate ID")
	}
	db.apps[appID] = &persistence.App{
		ID:            appID,
		Name:          name,
		MaxAccounts:   maxAccounts,
		AllowedOrigin: allowedOrigin,
		MailTemplates: mailTemplates,
		Admins:        admins,
		PrivateKey:    persistence.AppKey{Key: privateKey},
	}
	log.Info("%s", db)
	return db.apps[appID], nil
}

func (db *InMemoryDB) App(appID persistence.AppID) persistence.AppContext {
	return &InMemoryAppContext{
		db:    db,
		appID: appID,
	}
}

func (db *InMemoryDB) GetApp(appID persistence.AppID) *persistence.App {
	app := db.apps[appID]
	app.PublicKey = app.PrivateKey.EncodePublicKey()
	return app
}

func (db *InMemoryDB) GetAppByOrigin(origin string) *persistence.App {
	for _, app := range db.apps {
		if app.AllowedOrigin == origin {
			return app
		}
	}
	return nil
}

func (db *InMemoryDB) GetApps() []*persistence.App {
	res := make([]*persistence.App, len(db.apps))
	idx := 0
	for _, app := range db.apps {
		res[idx] = app
		idx++
	}
	return res
}
