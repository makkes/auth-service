package utils

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"golang.org/x/xerrors"

	uuid "github.com/gofrs/uuid"
	"github.com/makkes/services.makk.es/auth/persistence"
)

func createApp(db persistence.DB, app map[string]interface{}) error {
	appID, ok := app["id"].(string)
	if !ok {
		return xerrors.Errorf("app ID '%v' is not a string", app["id"])
	}
	res := make([]persistence.AccountID, 0)
	var mailTemplates persistence.MailTemplates
	if app["mailTemplates"] != nil {
		mailTemplates.ActivateAccount = app["mailTemplates"].(map[string]interface{})["activateAccount"].(string)
	}
	admins := make([]persistence.AccountID, 0)
	if app["admins"] != nil {
		adminsIf := app["admins"].([]interface{})
		admins = make([]persistence.AccountID, len(adminsIf))
		for idx, adm := range adminsIf {
			admins[idx], _ = persistence.NewAccountID(adm.(string))
		}
	}
	privKeyPem, _ := pem.Decode([]byte(app["privateKey"].(string)))
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err != nil {
		return xerrors.Errorf("error parsing private key of app %s: %w", appID, err)
	}
	savedApp, err := db.SaveApp(persistence.AppID{ID: appID}, app["name"].(string), int(app["maxAccounts"].(float64)), app["allowedOrigin"].(string), mailTemplates, admins, *privKey)
	if err != nil {
		return xerrors.Errorf("could not save app %s: %s", appID, err)
	}
	if app["users"] != nil {
		for _, accMapIf := range app["users"].([]interface{}) {
			accMap := accMapIf.(map[string]interface{})
			rolesIf := accMap["roles"].([]interface{})
			roles := make([]string, len(rolesIf))
			for i, v := range rolesIf {
				roles[i] = fmt.Sprint(v)
			}
			var newID uuid.UUID
			var err error
			if accMap["id"] != nil {
				newID, err = uuid.FromString(accMap["id"].(string))
			} else {
				newID, err = uuid.NewV4()
			}
			if err != nil {
				return xerrors.Errorf("error generating ID for preload user %s: %s", accMap, err)
			}
			hash, err := persistence.NewHash(accMap["password"].(string))
			if err != nil {
				return xerrors.Errorf("error generating password hash for preload user %s: %s", accMap, err)
			}
			newUser := persistence.Account{
				ID:           persistence.AccountID{UUID: newID},
				Email:        accMap["email"].(string),
				PasswordHash: hash,
				Active:       true,
				Roles:        roles,
			}
			err = db.App(savedApp.ID).SaveAccount(newUser)
			if err != nil {
				return xerrors.Errorf("error preloading user %s: %s", newUser, err)
			}
			if accMap["activationToken"] != nil {
				err := db.App(savedApp.ID).SaveActivationToken(newUser.ID, accMap["activationToken"].(string))
				if err != nil {
					return xerrors.Errorf("error saving activation token: %w", err)
				}
			}
			res = append(res, newUser.ID)
		}
	}
	return nil
}

func PreloadApps(db persistence.DB, fileName string) error {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return xerrors.Errorf("Error loading apps file: %w", err)
	}
	var apps map[string]interface{}
	err = json.Unmarshal(bytes, &apps)
	if err != nil {
		return xerrors.Errorf("cannot preload apps: %w", err)
	}
	adminApp := apps["admin"]
	createApp(db, adminApp.(map[string]interface{}))
	otherApps := apps["others"]
	if otherApps == nil {
		return nil
	}
	for _, app := range otherApps.([]interface{}) {
		err := createApp(db, app.(map[string]interface{}))
		if err != nil {
			return xerrors.Errorf("error creating app: %w", err)
		}
	}
	return nil
}
