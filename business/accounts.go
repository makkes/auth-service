package business

import (
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/mailer"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/utils"
	uuid "github.com/satori/go.uuid"
)

var ActivationError = errors.New("Account could not be activated")
var EmailExistsError = errors.New("An account with the email address already exists")
var AppQuotaExceeded = errors.New("Quota for this application has been reached")

type AccountCreation struct {
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Roles    []string
	Active   bool
}

func (u AccountCreation) Validate() ValidationResult {
	vr := ValidationResult{
		Errors: make(map[string]string),
	}
	u.Email = strings.TrimSpace(u.Email)
	if u.Email == "" {
		vr.Errors["email"] = "Dieses Feld darf nicht leer sein"
	}

	u.Password = strings.TrimSpace(u.Password)
	if u.Password == "" {
		vr.Errors["password"] = "Dieses Feld darf nicht leer sein"
	}

	return vr
}

type AccountService struct {
	db     persistence.DB
	mailer mailer.Mailer
}

func NewAccountService(db persistence.DB, mailer mailer.Mailer) *AccountService {
	return &AccountService{
		db:     db,
		mailer: mailer,
	}
}

type AppContext struct {
	accountService *AccountService
	app            *persistence.App
}

func (s *AccountService) NewAppContext(app *persistence.App) *AppContext {
	return &AppContext{s, app}
}

func (s *AccountService) CreateAuthenticationToken(privKey *rsa.PrivateKey, appID persistence.AppID, email, password string) (string, error) {
	account := s.db.App(appID).GetAccountByEmail(email)
	if account == nil || !account.Active || !account.PasswordHash.Matches(password) {
		return "", errors.New("Account doesn't exist, is inactive or password is wrong")
	}
	return utils.CreateJWT(privKey, account.ID, appID, time.Now())
}

func (ctx *AppContext) CreateAccount(u AccountCreation) (*persistence.Account, error) {
	// TODO: how do we implement quota enforcement?
	//if ctx.app.NumAccounts >= ctx.app.MaxAccounts {
	//log.Warn("App %s has exceeded the maximum number of accounts: %d", ctx.app.ID.String(), ctx.app.MaxAccounts)
	//return nil, AppQuotaExceeded
	//}
	existingAcc := ctx.accountService.db.App(ctx.app.ID).GetAccountByEmail(u.Email)
	if existingAcc != nil {
		return nil, EmailExistsError
	}
	newID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	hash, err := persistence.NewHash(u.Password)
	if err != nil {
		return nil, err
	}
	newUser := &persistence.Account{
		ID:           persistence.AccountID{newID},
		Email:        u.Email,
		Active:       u.Active,
		PasswordHash: hash,
		Roles:        u.Roles,
	}
	ctx.accountService.db.App(ctx.app.ID).SaveAccount(*newUser)
	if newUser.Active {
		return newUser, nil
	}

	activationToken, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	ctx.accountService.db.App(ctx.app.ID).SaveActivationToken(newUser.ID, activationToken.String())
	err = ctx.accountService.mailer.SendActivationMail(newUser.Email, activationToken.String(), newUser.ID, ctx.app.MailTemplates.ActivateAccount)
	if err != nil {
		log.Error("Error sending activation mail: %s", err)
	}
	return newUser, nil
}

func (s *AccountService) GetAccounts(appID persistence.AppID, authID persistence.AccountID) []*persistence.Account {
	account := s.db.App(appID).GetAccount(authID)
	if account == nil || !account.Active {
		return nil
	}
	if account.HasRole("admin") {
		return s.db.App(appID).GetAccounts()
	}
	return []*persistence.Account{account}
}

func (s *AccountService) GetAccount(appID persistence.AppID, authenticatedUserID persistence.AccountID, id persistence.AccountID) *persistence.Account {
	authenticatedUser := s.db.App(appID).GetAccount(authenticatedUserID)
	account := s.db.App(appID).GetAccount(id)
	if account != nil && ((account.ID == authenticatedUserID && account.Active) || authenticatedUser.HasRole("admin")) {
		return account
	}
	return nil
}

func (s *AccountService) ActivateAccount(appID persistence.AppID, activationToken string, accountID persistence.AccountID) error {
	storedActivationToken := s.db.App(appID).GetActivationToken(accountID)
	if storedActivationToken == "" || storedActivationToken != activationToken {
		return ActivationError
	}
	account := s.db.App(appID).GetAccount(accountID)
	if account == nil {
		return ActivationError
	}
	account.Active = true
	s.db.App(appID).SaveAccount(*account)
	s.db.App(appID).DeleteActivationToken(account.ID)
	return nil
}
