package postgres

import (
	"crypto/rsa"
	"database/sql"
	"fmt"

	"golang.org/x/xerrors"

	// blank import for letting pq registers itself with database/sql
	_ "github.com/lib/pq"
	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
)

const (
	sqlInsertApp = `INSERT INTO apps(id, name, max_accounts, allowed_origin, mail_templates, admins, private_key)
		VALUES($1, $2, $3, $4, $5, $6, $7)`
	sqlQueryApp               = `SELECT id, name, max_accounts, allowed_origin, mail_templates, admins, private_key FROM apps WHERE id = $1`
	sqlQueryApps              = `SELECT id, name, max_accounts, allowed_origin, mail_templates, admins, private_key FROM apps`
	sqlUpdateAppName          = `UPDATE apps SET name = $1 WHERE id = $2`
	sqlUpdateAppAllowedOrigin = `UPDATE apps SET allowed_origin = $1 WHERE id = $2`
	sqlDeleteApp              = `DELETE FROM apps WHERE id = $1`
	sqlInsertAccount          = `INSERT INTO accounts(id, app_id, email, roles, pw_hash, active)
		VALUES($1, $2, $3, $4, $5, $6)`
	sqlUpdateAccount               = `UPDATE accounts SET app_id = $2, email = $3, roles = $4, pw_hash = $5, active = $6 WHERE id = $1`
	sqlAccountExists               = `SELECT COUNT(*) FROM accounts WHERE id = $1`
	sqlQueryAccountByIDAndAppID    = `SELECT id, email, roles, pw_hash, active FROM accounts WHERE id = $1 AND app_id = $2`
	sqlQueryAccountByEmailAndAppID = `SELECT id, email, roles, pw_hash, active FROM accounts WHERE email = $1 AND app_id = $2`
	sqlQueryAccountsByAppID        = `SELECT id, email, roles, pw_hash, active FROM accounts WHERE app_id = $1`
	sqlInsertActivationToken       = `INSERT INTO activation_tokens(app_id, account_id, token)
		VALUES($1, $2, $3)`
	sqlQueryActivationToken  = `SELECT token FROM activation_tokens WHERE app_id = $1 and account_id = $2`
	sqlDeleteActivationToken = `DELETE FROM activation_tokens WHERE account_id = $1`
)

type PostgresDB struct {
	db  *sql.DB
	log log.Logger
}

type PostgresAppContext struct {
	db    *PostgresDB
	appID persistence.AppID
}

func NewPostgresDB(user, dbName, host, port, sslMode string) (*PostgresDB, error) {
	logger := log.NewDefaultLevelLogger("POSTGRES")
	connStr := fmt.Sprintf("user=%s dbname=%s host=%s port=%s sslmode=%s", user, dbName, host, port, sslMode)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	err = migrate(db)
	if err != nil {
		return nil, xerrors.Errorf("could not apply DB migrations: %w", err)
	}

	return &PostgresDB{db, logger}, nil
}

func (db *PostgresDB) GetApp(appID persistence.AppID) *persistence.App {
	var app persistence.App
	err := db.db.QueryRow(sqlQueryApp, appID.ID).Scan(&app.ID.ID, &app.Name, &app.MaxAccounts, &app.AllowedOrigin, &app.MailTemplates, &app.Admins, &app.PrivateKey)
	if err != nil {
		if err != sql.ErrNoRows {
			db.log.Error("Querying for app %s returned an error: %s", appID, err)
		}
		return nil
	}
	app.PublicKey = app.PrivateKey.EncodePublicKey()

	return &app
}

func (db *PostgresDB) App(appID persistence.AppID) persistence.AppContext {
	return &PostgresAppContext{
		db:    db,
		appID: appID,
	}
}

func (db *PostgresDB) SaveApp(id persistence.AppID, name string, maxAccounts int, allowedOrigin string, mailTemplates persistence.MailTemplates, admins persistence.AppAdmins, privateKey rsa.PrivateKey) (*persistence.App, error) {
	newApp := persistence.App{
		ID:            id,
		Name:          name,
		MaxAccounts:   maxAccounts,
		AllowedOrigin: allowedOrigin,
		MailTemplates: mailTemplates,
		Admins:        admins,
		PrivateKey:    persistence.AppKey{Key: privateKey},
	}
	newApp.PublicKey = newApp.PrivateKey.EncodePublicKey()

	_, err := db.db.Exec(sqlInsertApp, id.ID, name, maxAccounts, allowedOrigin, mailTemplates, admins, newApp.PrivateKey)
	if err != nil {
		return nil, xerrors.Errorf("error inserting app: %w", err)
	}
	return &newApp, nil
}

func (db *PostgresDB) DeleteApp(id persistence.AppID) error {
	if _, err := db.db.Exec(sqlDeleteApp, id.ID); err != nil {
		return xerrors.Errorf("error deleting app %s: %w", id, err)
	}
	return nil
}

func (db *PostgresDB) GetApps() []*persistence.App {
	var res []*persistence.App
	rows, err := db.db.Query(sqlQueryApps)
	if err != nil {
		db.log.Error("Querying for apps returned an error: %s", err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var app persistence.App
		err := rows.Scan(&app.ID.ID, &app.Name, &app.MaxAccounts, &app.AllowedOrigin, &app.MailTemplates, &app.Admins, &app.PrivateKey)
		if err != nil {
			db.log.Error("Scanning result row returned an error: %s", err)
			return nil
		}
		app.PublicKey = app.PrivateKey.EncodePublicKey()
		res = append(res, &app)
	}
	return res
}

func (ctx *PostgresAppContext) SaveActivationToken(accountID persistence.AccountID, token string) error {
	tx, err := ctx.db.db.Begin()
	if err != nil {
		tx.Rollback()
		return xerrors.Errorf("could not start transaction: %w", err)
	}

	var accountCnt int
	if err := tx.QueryRow(sqlAccountExists, accountID.UUID.String()).Scan(&accountCnt); err != nil {
		tx.Rollback()
		return xerrors.Errorf("error querying for existing account %s in token table: %w", err)
	}
	if accountCnt == 0 {
		tx.Rollback()
		return xerrors.Errorf("account %s doesn't exists, no token can be saved", accountID)
	}
	if _, err := tx.Exec(sqlInsertActivationToken, ctx.appID.ID, accountID.UUID.String(), token); err != nil {
		tx.Rollback()
		return xerrors.Errorf("error inserting activation token for account %s: %w", accountID, err)
	}
	if err = tx.Commit(); err != nil {
		return xerrors.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func (ctx *PostgresAppContext) GetAccountByEmail(email string) *persistence.Account {
	var account persistence.Account
	err := ctx.db.db.QueryRow(sqlQueryAccountByEmailAndAppID, email, ctx.appID.ID).Scan(&account.ID, &account.Email, &account.Roles, &account.PasswordHash, &account.Active)
	if err != nil {
		if err != sql.ErrNoRows {
			ctx.db.log.Error("Querying for account %s in app %s returned an error: %s", email, ctx.appID, err)
		}
		return nil
	}
	return &account
}

func (ctx *PostgresAppContext) GetActivationToken(id persistence.AccountID) string {
	var token string
	err := ctx.db.db.QueryRow(sqlQueryActivationToken, ctx.appID.ID, id).Scan(&token)
	if err != nil {
		if err != sql.ErrNoRows {
			ctx.db.log.Error("Querying for activation token for account %s in app %s returned an error: %s", id, ctx.appID, err)
		}
		return ""
	}
	return token
}

func (ctx *PostgresAppContext) DeleteActivationToken(id persistence.AccountID) error {
	_, err := ctx.db.db.Exec(sqlDeleteActivationToken, id.UUID.String())
	if err != nil {
		return xerrors.Errorf("error deleting activation token for account %s: %w", id, err)
	}
	return nil
}

func (ctx *PostgresAppContext) SaveAccount(account persistence.Account) error {
	existingAccount := ctx.GetAccount(account.ID)
	var err error
	if existingAccount != nil {
		ctx.db.log.Debug("Updating account %s", account.ID)
		_, err = ctx.db.db.Exec(sqlUpdateAccount, account.ID.UUID.String(), ctx.appID.ID, account.Email, account.Roles, account.PasswordHash, account.Active)
	} else {
		ctx.db.log.Debug("Inserting account %s", account.ID)
		_, err = ctx.db.db.Exec(sqlInsertAccount, account.ID.UUID.String(), ctx.appID.ID, account.Email, account.Roles, account.PasswordHash, account.Active)
	}
	if err != nil {
		return xerrors.Errorf("Error inserting or updating account %v: %w", account, err)
	}
	ctx.db.log.Debug("Persisted account %#v", account)
	return nil
}

func (ctx *PostgresAppContext) GetAccount(id persistence.AccountID) *persistence.Account {
	var account persistence.Account
	err := ctx.db.db.QueryRow(sqlQueryAccountByIDAndAppID, id.UUID.String(), ctx.appID.ID).Scan(&account.ID, &account.Email, &account.Roles, &account.PasswordHash, &account.Active)
	if err != nil {
		if err != sql.ErrNoRows {
			ctx.db.log.Error("Querying for account %s in app %s returned an error: %s", id, ctx.appID, err)
		}
		return nil
	}
	return &account
}

func (ctx *PostgresAppContext) GetAccounts() []*persistence.Account {
	var res []*persistence.Account
	rows, err := ctx.db.db.Query(sqlQueryAccountsByAppID, ctx.appID.ID)
	if err != nil {
		ctx.db.log.Error("Querying for accounts in app %s returned an error: %s", ctx.appID, err)
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var account persistence.Account
		err := rows.Scan(&account.ID, &account.Email, &account.Roles, &account.PasswordHash, &account.Active)
		if err != nil {
			ctx.db.log.Error("Scanning result row returned an error: %s", err)
			return nil
		}
		res = append(res, &account)
	}
	return res
}

func (ctx *PostgresAppContext) UpdateAppName(newName string) error {
	res, err := ctx.db.db.Exec(sqlUpdateAppName, newName, ctx.appID.ID)
	if err != nil {
		return xerrors.Errorf("error updating name of app '%s': %w", ctx.appID, err)
	}
	rowsUpdated, err := res.RowsAffected()
	if err != nil {
		return xerrors.Errorf("could not get the number of affected rows: %w", err)
	}
	if rowsUpdated == 0 {
		return xerrors.Errorf("app '%s' doesn't seem to exist", ctx.appID)
	}
	return nil
}

func (ctx *PostgresAppContext) UpdateAppOrigin(newOrigin string) error {
	res, err := ctx.db.db.Exec(sqlUpdateAppAllowedOrigin, newOrigin, ctx.appID.ID)
	if err != nil {
		return xerrors.Errorf("error updating allowed origin of app '%s': %w", ctx.appID, err)
	}
	rowsUpdated, err := res.RowsAffected()
	if err != nil {
		return xerrors.Errorf("could not get the number of affected rows: %w", err)
	}
	if rowsUpdated == 0 {
		return xerrors.Errorf("app '%s' doesn't seem to exist", ctx.appID)
	}
	return nil
}
