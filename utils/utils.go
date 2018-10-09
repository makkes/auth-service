package utils

import (
	"encoding/json"
	"net/http"

	log "github.com/makkes/justlib/logging"
)

func ReplyJSON(w http.ResponseWriter, status int, res interface{}, headers map[string]string) {
	marshalledRes, err := json.Marshal(res)
	if err != nil {
		log.Error("Error marshalling result %s: %s", res, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(marshalledRes)
}
