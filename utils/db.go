package utils

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
	uuid "github.com/satori/go.uuid"
)

func createApp(db persistence.DB, app map[string]interface{}) []persistence.AccountID {
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
		log.Error("Error parsing private key: %s", err)
		return nil
	}
	savedApp, _ := db.SaveApp(persistence.AppID{ID: app["id"].(string)}, app["name"].(string), int(app["maxAccounts"].(float64)), app["allowedOrigin"].(string), mailTemplates, admins, *privKey)
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
				log.Error("Error generating ID for preload user %s: %s", accMap, err)
				continue
			}
			hash, err := persistence.NewHash(accMap["password"].(string))
			if err != nil {
				log.Error("Error generating password hash for preload user %s: %s", accMap, err)
				continue
			}
			newUser := persistence.Account{
				ID:           persistence.AccountID{newID},
				Email:        accMap["email"].(string),
				PasswordHash: hash,
				Active:       true,
				Roles:        roles,
			}
			db.App(savedApp.ID).SaveAccount(newUser)
			if accMap["activationToken"] != nil {
				db.App(savedApp.ID).SaveActivationToken(newUser.ID, accMap["activationToken"].(string))
			}
			res = append(res, newUser.ID)
			if err != nil {
				log.Error("Error preloading user %s: %s", newUser, err)
			}
		}
	}
	return res
}

func PreloadApps(db persistence.DB, fileName string) {
	bytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Error loading apps file: %s", err)
		return
	}
	var apps map[string]interface{}
	err = json.Unmarshal(bytes, &apps)
	if err != nil {
		log.Error("Cannot preload apps: %s", err)
		return
	}
	adminApp := apps["admin"]
	createApp(db, adminApp.(map[string]interface{}))
	otherApps := apps["others"]
	for _, app := range otherApps.([]interface{}) {
		createApp(db, app.(map[string]interface{}))
	}
}
