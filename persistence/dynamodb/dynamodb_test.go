package dynamodb

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/makkes/assert"
	log "github.com/makkes/justlib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/makkes/services.makk.es/auth/utils"
	"github.com/satori/go.uuid"
)

var testTableName = fmt.Sprintf("auth.test.%d", time.Now().Unix())

func TestMain(m *testing.M) {
	log.SetLevel(log.WARN)
	db, _ := NewDynamoDB(testTableName)
	utils.PreloadApps(db, "test-apps.json")
	code := m.Run()
	_, err := db.svc.DeleteTable(&dynamodb.DeleteTableInput{
		TableName: aws.String(testTableName),
	})
	if err != nil {
		fmt.Printf("Error deleting test table: %s", err)
		code = 999
	}
	os.Exit(code)
}

func TestDBCreation(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	// the compiler ascertains for us that DynamoDB implements persistence.DB
	func(db persistence.DB) {}(db)

	assert.NotNil(db, "Dynamo DB is nil")
}

func TestGetAppReturnsNilForUnknownApp(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	app := db.GetApp(persistence.AppID{ID: "nothing to see here"})

	assert.Nil(app, "Expected to get no app")
}

func TestGetAppReturnsNilForEmptyAppID(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	app := db.GetApp(persistence.AppID{})

	assert.Nil(app, "Expected to get no app")
}

func TestGetAppReturnsApp(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

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

func TestAppReturnsAppContext(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	appCtx, ok := db.App(persistence.AppID{ID: "some ID"}).(*DynamoDBAppContext)

	assert.True(ok, "returned value is not of type DynamoDBAppContext")
	assert.Equal(appCtx.appID, persistence.AppID{ID: "some ID"}, "got unexpected app ID")
	assert.Equal(appCtx.db, db, "got unexpected db pointer")
}

func TestGetAppsReturnsAllApps(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

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
	db, _ := NewDynamoDB(testTableName)

	account := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).GetAccount(persistence.AccountID{})

	assert.Nil(account, "Expected to get a no account")
}

func TestGetAccountReturnsNilForUnknownApp(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	uid, _ := uuid.FromString("66efbaf2-3417-4df4-a477-239af136e0d3")
	account := db.App(persistence.AppID{ID: "does not exist"}).GetAccount(persistence.AccountID{uid})

	assert.Nil(account, "Expected to get a no account")
}

func TestGetAccountReturnsAccount(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

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

func TestGetAccountByEmailForNonExistantApp(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	account := db.App(persistence.AppID{ID: "does not exist"}).GetAccountByEmail("does not exist")

	assert.Nil(account, "We expected no account to be found")
}

func TestGetAccountByEmailIsNil(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	account := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetAccountByEmail("does not exist")

	assert.Nil(account, "We expected no account to be found")
}

func TestGetAccountByEmail(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	account := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).GetAccountByEmail("mail@makk.es")

	assert.NotNil(account, "Account was not retrieved")
	assert.Equal(account.Email, "mail@makk.es", "Account has unexpected email address")
}

func TestGetAccounts(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	accounts := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetAccounts()

	assert.True(len(accounts) == 3, fmt.Sprintf("We expected three accounts to be found but found %d (%v)", len(accounts), accounts))
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
	db, _ := NewDynamoDB(testTableName)
	err := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).SaveActivationToken(randomAccountID(), "token")

	assert.NotNil(err, "We expected an error to occur when saving an activation token with a non-existant account ID")
}

func TestSaveActivationTokenSuccess(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)
	uid, _ := uuid.FromString("66efbaf2-3417-4df4-a477-239af136e0d3")
	err := db.App(persistence.AppID{ID: "c04aac4e-6185-43db-9054-13b0774dae9e"}).SaveActivationToken(persistence.AccountID{uid}, "token")

	assert.Nil(err, "We expected no error to occur when saving an activation token with an existing account ID")
}

func TestActivationTokenEmpty(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	token := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetActivationToken(randomAccountID())

	assert.Equal(token, "", "We expected to get no activation token for a non-existant account")
}

func TestActivationToken(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	token := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).GetActivationToken(persistence.AccountID{UUID: uuid.FromStringOrNil("ff046952-9fa3-4ec9-89ba-b602a8f22e4f")})

	assert.True(len(token) > 0, "We expected to get an activation token")
}

func TestDeleteActivationToken(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	err := db.App(persistence.AppID{ID: "0a791409-d58d-4175-ba02-2bdbdb8e6629"}).DeleteActivationToken(persistence.AccountID{UUID: uuid.FromStringOrNil("ff046952-9fa3-4ec9-89ba-b602a8f22e4f")})

	assert.Nil(err, "We should have gotten no error")
}

func TestSaveAppHappyPath(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	adminID, _ := uuid.FromString("492c0de9-b072-49a3-8b75-127dc19c358c")
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"anewappid"}, "a new app", 99, "https://anewapp.io", persistence.MailTemplates{ActivateAccount: "welcome, man"}, []persistence.AccountID{persistence.AccountID{adminID}}, *privKey)
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
	db, _ := NewDynamoDB(testTableName)

	err := db.App(persistence.AppID{"does not exist"}).UpdateAppName("new name")

	assert.NotNil(err, "Expected an error")
}

func TestUpdateAppNameSucceeds(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

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
	db, _ := NewDynamoDB(testTableName)

	err := db.App(persistence.AppID{"does not exist"}).UpdateAppOrigin("new origin")

	assert.NotNil(err, "Expected an error")
}

func TestUpdateAppOriginSucceeds(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

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
	db, _ := NewDynamoDB(testTableName)

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
	db, _ := NewDynamoDB(testTableName)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"c04aac4e-6185-43db-9054-13b0774dae9e"}, "another_app", 99, "https://anewapp.io", persistence.MailTemplates{}, nil, *privKey)
	assert.Nil(res, "We expected an error")
	assert.NotNil(err, "We expected a nil app")
}

func TestSaveAppSucceedsWithDuplicateOrigin(t *testing.T) {
	assert := assert.NewStrict(t)
	db, _ := NewDynamoDB(testTableName)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	res, err := db.SaveApp(persistence.AppID{"anewapp2id"}, "a new app 2", 99, "https://anewapp.io", persistence.MailTemplates{}, nil, *privKey)
	assert.Nil(err, "We didn't expect an error")
	assert.NotNil(res, "We expected a non-nil app")
}
