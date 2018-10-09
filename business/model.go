package business

import (
	"github.com/makkes/services.makk.es/auth/persistence"
)

type ValidationResult struct {
	Errors map[string]string
}

func (vr ValidationResult) HasErrors() bool {
	return len(vr.Errors) > 0
}

type Validatable interface {
	Validate() ValidationResult
}

type Authentication struct {
	Account persistence.Account
	App     persistence.App
}
