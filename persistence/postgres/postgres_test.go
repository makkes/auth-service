// +build integration postgres

package postgres_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"flag"
	"fmt"
	mathrand "math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	log "github.com/makkes/golib/logging"

	"github.com/gofrs/uuid"
	"github.com/makkes/assert"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/persistence/postgres"
	"github.com/makkes/services.makk.es/auth/utils"
)

var (
	bootstrapCommands = []string{
		"docker run -d --name postgres -v pgdata:/var/lib/postgresql/data -p 5432:5432 postgres:12",
		"docker exec -it postgres createuser -U postgres auth",
	}
	db                persistence.DB
	containerName     string
	containerPort     = "5432"
	bootstrapDatabase = flag.Bool("bootstrap-database", false, "")
)

func startDatabase() {
	mathrand.Seed(time.Now().UnixNano())
	rnd := make([]byte, 3)
	mathrand.Read(rnd)
	containerName = fmt.Sprintf("postgres-test-%s", hex.EncodeToString(rnd))
	containerPort = strconv.Itoa(mathrand.Intn(65536-1024) + 1024)

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cmdCancel()
	cmd := exec.CommandContext(cmdCtx, "docker", "run", "-d", "--name", containerName, "-p", containerPort+":5432", "postgres:12")
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting database container: %s\n", err)
		os.Exit(1)
	}
}

func stopDatabase() {
	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cmdCancel()
	cmd := exec.CommandContext(cmdCtx, "docker", "stop", containerName)
	err := cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping database container: %s\n", err)
		os.Exit(1)
	}
	cmd = exec.CommandContext(cmdCtx, "docker", "rm", containerName)
	err = cmd.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error removing database container: %s\n", err)
		os.Exit(1)
	}
}

func TestMain(m *testing.M) {
	log.SetLevel(log.WARN)
	flag.Parse()

	if *bootstrapDatabase {
		startDatabase()
		time.Sleep(2 * time.Second)
	}

	var err error
	db, err = postgres.NewPostgresDB("postgres", "", "postgres", "localhost", containerPort, "disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initiating PostgreSQL backend: %s\n", err)
		if *bootstrapDatabase {
			stopDatabase()
		}
		os.Exit(1)
	}
	err = utils.PreloadApps(db, "test-apps.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error preloading data: %s\n", err)
		if *bootstrapDatabase {
			stopDatabase()
		}
		os.Exit(1)
	}
	code := m.Run()
	if *bootstrapDatabase {
		stopDatabase()
	}
	os.Exit(code)
}

func TestDBCreation(t *testing.T) {
	assert := assert.NewStrict(t)

	// the compiler ascertains for us that PostgresDB implements persistence.DB
	func(db persistence.DB) {}(db)

	assert.NotNil(db, "DB is nil")
}

func TestGetAppReturnsNilForUnknownApp(t *testing.T) {
	assert := assert.NewStrict(t)

	app := db.GetApp(persistence.AppID{ID: "nothing to see here"})

	assert.Nil(app, "Expected to get no app")
}

func TestGetAppReturnsNilForEmptyAppID(t *testing.T) {
	assert := assert.NewStrict(t)

	app := db.GetApp(persistence.AppID{})

	assert.Nil(app, "Expected to get no app")
}

func TestGetAppReturnsApp(t *testing.T) {
	assert := assert.NewStrict(t)

	app := db.GetApp(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"})

	assert.NotNil(app, "Expected to get app")
	assert.Equal(app.ID, persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}, "App ID is different")
	assert.Equal(app.MaxAccounts, 5, "max accounts number is different")
	assert.Equal(app.MailTemplates, persistence.MailTemplates{}, "mail templates are different")
	assert.Equal(app.AllowedOrigin, "http://another.app.com", "allowed origin is different")
	assert.Equal(len(app.Admins), 1, "Number of admins is different")
	assert.Equal(app.Admins[0].String(), "b1ee9d2c-d252-4c45-a524-48e3d6da24c1", "Got unexpected admin")

	assert.Match("^-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----$", strings.Replace(app.PublicKey, "\n", "", -1), "Unexpected public key")
}

func TestGetAppsReturnsAllApps(t *testing.T) {
	assert := assert.NewStrict(t)

	apps := db.GetApps()

	assert.True(len(apps) == 3, fmt.Sprintf("Expected 3 apps but got %d", len(apps)))
	ids := map[string]*persistence.App{apps[0].ID.ID: apps[0], apps[1].ID.ID: apps[1], apps[2].ID.ID: apps[2]}

	adminApp := ids["0a791409-d58d-4175-ba02-2bdbdb8e6629"]
	assert.NotNil(adminApp, "Expected admin app to be defined")
	assert.Equal(adminApp.MaxAccounts, 2147483647, "Got unexpected max number of accounts in admin app")
	assert.Equal(adminApp.AllowedOrigin, "http://localhost:4243", "Got unexpected allowed origin in admin app")
	assert.True(strings.Contains(adminApp.MailTemplates.ActivateAccount, "Activate your Makk.es Services account"), "Got unexpected mail templates in admin app")
	assert.Equal(len(adminApp.Admins), 0, "Got unexpected number of admins in admin app")
	assert.Match("^-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----$", strings.Replace(adminApp.PublicKey, "\n", "", -1), "Unexpected public key")

	anotherApp := ids["c04aac4e-6185-43db-9054-13b0774dae9e"]
	assert.NotNil(anotherApp, "Expected another_app app to be defined")
	assert.Equal(anotherApp.MaxAccounts, 5, "Got unexpected max number of accounts in another_app app")
	assert.Equal(anotherApp.AllowedOrigin, "http://another.app.com", "Got unexpected allowed origin in another_app app")
	assert.True(strings.Contains(anotherApp.MailTemplates.ActivateAccount, ""), "Got unexpected mail templates in another_app app")
	assert.Equal(len(anotherApp.Admins), 1, fmt.Sprintf("Got unexpected number of admins in another_app app. Admins: %s", anotherApp.Admins))
	assert.Equal(anotherApp.Admins[0].String(), "b1ee9d2c-d252-4c45-a524-48e3d6da24c1", "Got unexpected admin in another_app app")
	assert.Match("^-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----$", strings.Replace(anotherApp.PublicKey, "\n", "", -1), "Unexpected public key")

}

func TestGetAccountReturnsNilForUnknownAccount(t *testing.T) {
	assert := assert.NewStrict(t)

	account := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).GetAccount(persistence.AccountID{})

	assert.Nil(account, "Expected to get a no account")
}

func TestGetAccountReturnsNilForUnknownApp(t *testing.T) {
	assert := assert.NewStrict(t)

	uid, _ := uuid.FromString("66efbaf2-3417-4df4-a477-239af136e0d3")
	account := db.App(persistence.AppID{ID: "does not exist"}).GetAccount(persistence.AccountID{uid})

	assert.Nil(account, "Expected to get a no account")
}

func TestGetAccountReturnsAccount(t *testing.T) {
	assert := assert.NewStrict(t)

	uid, _ := uuid.FromString("e8fc7d47-aba3-40db-afdb-5caddd6fd9dd")
	account := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).GetAccount(persistence.AccountID{uid})

	assert.NotNil(account, "Expected to get a no account")
	assert.Equal(account.ID, persistence.AccountID{uid}, "ID is different")
	assert.Equal(len(account.Roles), 1, "roles are different")
	assert.Equal(account.Roles[0], "admin", "roles are different")
	assert.Equal(account.Email, "admin@example.org", "email is different")
	assert.True(account.Active, "account should be active")
	assert.Equal(len(account.PasswordHash.Hash), 32, "passwordHash doesn't have expected size")
}

func TestGetAccountByEmailForNonexistentApp(t *testing.T) {
	assert := assert.NewStrict(t)

	account := db.App(persistence.AppID{ID: "does not exist"}).GetAccountByEmail("does not exist")

	assert.Nil(account, "We expected no account to be found")
}

func TestGetAccountByEmailIsNil(t *testing.T) {
	assert := assert.NewStrict(t)

	account := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetAccountByEmail("does not exist")

	assert.Nil(account, "We expected no account to be found")
}

func TestGetAccountByEmail(t *testing.T) {
	assert := assert.NewStrict(t)

	account := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).GetAccountByEmail("mail@makk.es")

	assert.NotNil(account, "Account was not retrieved")
	assert.Equal(account.Email, "mail@makk.es", "Account has unexpected email address")
}

func TestGetAccounts(t *testing.T) {
	assert := assert.NewStrict(t)

	accounts := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetAccounts()

	assert.True(len(accounts) == 3, fmt.Sprintf("We expected three accounts to be found but found %d (%v)", len(accounts), accounts))
}

func TestDeleteAccount(t *testing.T) {
	tests := []struct {
		name string
		in   persistence.AccountID
		err  bool
	}{
		{
			name: "non-existing account",
			in:   persistence.AccountID{UUID: uuid.FromStringOrNil("99652960-DD84-457A-826E-73794CFB3208")},
			err:  false,
		},
		{
			name: "success",
			in:   persistence.AccountID{UUID: uuid.FromStringOrNil("7AEDFD0E-513A-44F2-9C16-FCFD5A08DD61")},
			err:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.NewStrict(t)
			appCtx := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"})
			out := appCtx.DeleteAccount(tt.in)
			if tt.err {
				assert.NotNil(out, "Expected non-nil error")
			} else {
				assert.Nil(out, "Expected nil error")
			}
		})
	}
}

func randomAccountID() persistence.AccountID {
	uid, err := uuid.NewV4()
	if err != nil {
		panic("Unable to generate account ID")
	}

	return persistence.AccountID{UUID: uid}
}

func TestSaveActivationTokenError(t *testing.T) {
	assert := assert.NewStrict(t)
	err := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).SaveActivationToken(randomAccountID(), "token")

	assert.NotNil(err, "We expected an error to occur when saving an activation token with a non-existent account ID")
}

func TestSaveActivationTokenSuccess(t *testing.T) {
	assert := assert.NewStrict(t)
	uid, _ := uuid.FromString("66efbaf2-3417-4df4-a477-239af136e0d3")
	err := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).SaveActivationToken(persistence.AccountID{uid}, "token")

	assert.Nil(err, "We expected no error to occur when saving an activation token with an existing account ID")
}

func TestActivationTokenEmpty(t *testing.T) {
	assert := assert.NewStrict(t)

	token := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetActivationToken(randomAccountID())

	assert.Equal(token, "", "We expected to get no activation token for a non-existent account")
}

func TestActivationToken(t *testing.T) {
	assert := assert.NewStrict(t)

	token := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetActivationToken(persistence.AccountID{UUID: uuid.FromStringOrNil("ff046952-9fa3-4ec9-89ba-b602a8f22e4f")})

	assert.True(len(token) > 0, "We expected to get an activation token")
}

func TestDeleteActivationToken(t *testing.T) {
	assert := assert.NewStrict(t)

	err := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).DeleteActivationToken(persistence.AccountID{UUID: uuid.FromStringOrNil("ff046952-9fa3-4ec9-89ba-b602a8f22e4f")})

	assert.Nil(err, "We should have gotten no error")
}

func TestSaveAppHappyPath(t *testing.T) {
	assert := assert.NewStrict(t)

	adminID, _ := uuid.FromString("492c0de9-b072-49a3-8b75-127dc19c358c")
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"anewappid"}, "a new app", 99, "https://anewapp.io", persistence.MailTemplates{ActivateAccount: "welcome, man"}, []persistence.AccountID{{adminID}}, *privKey)
	assert.Nil(err, "We didn't expect an error")
	assert.NotNil(res, "We expected a non-nil app")

	app := db.GetApp(res.ID)
	assert.NotNil(res, "We expected a non-nil app")
	assert.Equal(app.ID, persistence.AppID{ID: "anewappid"}, "App ID is different")
	assert.Equal(app.MaxAccounts, 99, "max accounts number is different")
	assert.Equal(app.MailTemplates, persistence.MailTemplates{ActivateAccount: "welcome, man"}, "mail templates are different")
	assert.Equal(app.AllowedOrigin, "https://anewapp.io", "allowed origin is different")
	assert.Equal(len(app.Admins), 1, "Number of admins is different")
	assert.Equal(app.Admins[0].String(), "492c0de9-b072-49a3-8b75-127dc19c358c", "Got unexpected admin")

	assert.Equal(app.ID, res.ID, "App ID is different")
	assert.Equal(app.MaxAccounts, res.MaxAccounts, "max accounts number is different")
	assert.Equal(app.MailTemplates, res.MailTemplates, "mail templates are different")
	assert.Equal(app.AllowedOrigin, res.AllowedOrigin, "allowed origin is different")
	assert.Equal(len(app.Admins), len(res.Admins), "Number of admins is different")
	assert.Equal(app.Admins[0], res.Admins[0], "Got unexpected admin")
	assert.Equal(res.PublicKey, app.PublicKey, "Public keys differ")
}

func TestUpdateAppNameFailsIfAppDoesNotExist(t *testing.T) {
	assert := assert.NewStrict(t)

	err := db.App(persistence.AppID{"does not exist"}).UpdateAppName("new name")

	assert.NotNil(err, "Expected an error")
}

func TestUpdateAppNameSucceeds(t *testing.T) {
	assert := assert.NewStrict(t)

	appID := persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"}
	app := db.GetApp(appID)
	assert.Equal(app.Name, "admin", "Expected another app name")
	err := db.App(appID).UpdateAppName("new name")
	assert.Nil(err, "Expected no error")
	app = db.GetApp(appID)
	assert.Equal(app.Name, "new name", "Expected new app name")
}

func TestUpdateAppOriginFailsIfAppDoesNotExist(t *testing.T) {
	assert := assert.NewStrict(t)

	err := db.App(persistence.AppID{"does not exist"}).UpdateAppOrigin("new origin")

	assert.NotNil(err, "Expected an error")
}

func TestUpdateAppOriginSucceeds(t *testing.T) {
	assert := assert.NewStrict(t)

	appID := persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"}
	app := db.GetApp(appID)
	assert.Equal(app.AllowedOrigin, "http://localhost:4243", "Expected another app origin")
	err := db.App(appID).UpdateAppOrigin("new origin")
	assert.Nil(err, "Expected no error")
	app = db.GetApp(appID)
	assert.Equal(app.AllowedOrigin, "new origin", "Expected new app origin")
}

func TestDeleteAppSucceeds(t *testing.T) {
	assert := assert.NewStrict(t)

	appID := persistence.AppID{"c7d1a9d5-c211-4fd6-a275-393c8750cd9e"}
	app := db.GetApp(appID)
	assert.NotNil(app, "Expected app to exist. Perhaps the bootstrap data is broken.")
	accounts := db.App(appID).GetAccounts()
	assert.Equal(len(accounts), 2, "Expected two accounts to exist in app")
	err := db.DeleteApp(appID)
	assert.Nil(err, "Expected no error when deleting app")
	app = db.GetApp(appID)
	assert.Nil(app, "Expected app to be deleted")
	accounts = db.App(appID).GetAccounts()
	assert.Equal(len(accounts), 0, "Expected all accounts to be deleted")
}

func TestSaveAppFailsWithDuplicateAppID(t *testing.T) {
	assert := assert.NewStrict(t)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"c04aac4e-6185-43db-9054-13b0774dae9e"}, "another_app", 99, "https://anewapp.io", persistence.MailTemplates{}, nil, *privKey)
	assert.Nil(res, "We expected an error")
	assert.NotNil(err, "We expected a nil app")
}

func TestSaveAppSucceedsWithDuplicateOrigin(t *testing.T) {
	assert := assert.NewStrict(t)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"anewapp2id"}, "a new app 2", 99, "https://anewapp.io", persistence.MailTemplates{}, nil, *privKey)
	assert.Nil(err, "We didn't expect an error")
	assert.NotNil(res, "We expected a non-nil app")
}
