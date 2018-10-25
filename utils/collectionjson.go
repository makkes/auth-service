package utils

import (
	"encoding/json"
	"net/http"

	"github.com/jtacoma/uritemplates"
	log "github.com/makkes/golib/logging"
	"github.com/makkes/services.makk.es/auth/persistence"
)

type Data struct {
	Name   string `json:"name"`
	Prompt string `json:"prompt"`
	Value  string `json:"value"`
}

type LinkRelation struct {
	Rel         string
	UriTemplate string
}

func (lr LinkRelation) toLink(baseURL string, vars map[string]interface{}) Link {
	tmpl, err := uritemplates.Parse(lr.UriTemplate)
	if err != nil {
		log.Error("Error parsing URI template '%s': %s", lr.UriTemplate, err)
	}
	expanded, err := tmpl.Expand(vars)
	if err != nil {
		log.Error("Error expanding URI template '%s': %s", lr.UriTemplate, err)
	}
	return Link{
		Href: baseURL + expanded,
		Rel:  lr.Rel,
	}
}

var (
	AccountRelation LinkRelation = LinkRelation{"https://rel.services.makk.es/account", "/accounts/{id}"}
	ActiveRelation  LinkRelation = LinkRelation{"https://rel.services.makk.es/account/active", "/accounts/{id}/active"}
	RolesRelation   LinkRelation = LinkRelation{"https://rel.services.makk.es/account/roles", "/accounts/{id}/roles"}
	AppRelation     LinkRelation = LinkRelation{"https://rel.services.makk.es/app", "/apps/{id}"}
)

type Link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

type Item struct {
	Href  string `json:"href"`
	Data  []Data `json:"data,omitempty"`
	Links []Link `json:"links,omitempty"`
}

type Collection struct {
	Version string `json:"version"`
	Href    string `json:"href"`
	Items   []Item `json:"items"`
}

type CollectionJSON struct {
	Collection Collection `json:"collection"`
}

func WriteAppsAsCollectionJSON(w http.ResponseWriter, baseURL string, apps []*persistence.App) {
	items := make([]Item, 0)
	for _, app := range apps {
		item := Item{
			Href: AppRelation.toLink(baseURL, map[string]interface{}{"id": app.ID.String()}).Href,
		}
		items = append(items, item)
	}
	collection := Collection{
		Version: "1.0",
		Href:    baseURL + "/apps",
		Items:   items,
	}
	collJSON := CollectionJSON{
		Collection: collection,
	}

	res, err := json.Marshal(collJSON)
	if err != nil {
		log.Error("Error marshalling result %s: %s", collection, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.collection+json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func WriteAccountsAsCollectionJSON(w http.ResponseWriter, baseURL string, accounts []*persistence.Account) {
	items := make([]Item, 0)
	for _, account := range accounts {
		item := Item{
			Href: AccountRelation.toLink(baseURL, map[string]interface{}{"id": account.ID.String()}).Href,
			Links: []Link{
				AccountRelation.toLink(baseURL, map[string]interface{}{"id": account.ID.String()}),
				ActiveRelation.toLink(baseURL, map[string]interface{}{"id": account.ID.String()}),
				RolesRelation.toLink(baseURL, map[string]interface{}{"id": account.ID.String()}),
			},
		}
		items = append(items, item)
	}

	collection := Collection{
		Version: "1.0",
		Href:    baseURL + "/accounts",
		Items:   items,
	}
	collJSON := CollectionJSON{
		Collection: collection,
	}

	res, err := json.Marshal(collJSON)
	if err != nil {
		log.Error("Error marshalling result %s: %s", collection, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.collection+json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}
