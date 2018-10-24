package business

import (
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/justsocialapps/assert"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/mock"
)

func TestGetAppShouldReturnNilIfUserIsUnknown(t *testing.T) {
	assert := assert.NewAssert(t)

	// given
	mockDB, mockAppCtx, accountID, appID, ctxApp := setupMocks(persistence.AppID{"context app app"})
	mockDB.On("App", ctxApp.ID).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", accountID).Return(nil)
	service := NewAppService(mockDB)

	// when
	app := service.GetApp(ctxApp.ID, accountID, appID)

	// then
	assert.Nil(app, "App should be nil")
	mockDB.AssertExpectations(t)
}

func TestGetAppShouldReturnNilIfCtxAppIsNotAdminApp(t *testing.T) {
	assert := assert.NewAssert(t)

	// given
	mockDB, mockAppCtx, accountID, appID, ctxApp := setupMocks(persistence.AppID{"not admin app"})
	mockDB.On("App", ctxApp.ID).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", accountID).Return(&persistence.Account{})
	service := NewAppService(mockDB)

	// when
	app := service.GetApp(ctxApp.ID, accountID, appID)

	// then
	assert.Nil(app, "App should be nil")
	mockDB.AssertExpectations(t)
}

func TestGetAppShouldReturnAppIfCtxAppIsAdminApp(t *testing.T) {
	assert := assert.NewAssert(t)

	// given
	mockDB, mockAppCtx, accountID, appID, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "Ctx App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	mockDB.On("App", ctxApp.ID).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", accountID).Return(&persistence.Account{})
	mockDB.On("GetApp", appID).Return(resApp)
	service := NewAppService(mockDB)

	// when
	app := service.GetApp(ctxApp.ID, accountID, appID)

	// then
	assert.NotNil(app, "App should not be nil")
	assert.Equal(app, resApp, "Service returned unexpected app")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)
}

func TestCreateAppShouldFailWhenNotInAdminApp(t *testing.T) {
	assert := assert.NewAssert(t)

	service := NewAppService(nil).NewAuthCtx(Authentication{
		Account: persistence.Account{},
		App:     persistence.App{ID: persistence.AppID{"not admin app"}},
	})
	res, err := service.CreateApp(AppCreation{}, nil)

	assert.Nil(res, "Expected nil result")
	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(err, ErrReproductionDenied, "Expected a different error")
}

func TestCreateAppShouldFailWhenDBFails(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, _, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	service := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{},
		App:     persistence.App{ID: ctxApp.ID},
	})
	mockDB.On("SaveApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, fmt.Errorf("DB error"))
	res, err := service.CreateApp(AppCreation{}, nil)

	assert.Nil(res, "Expected nil result")
	assert.NotNil(err, "Expected non-nil error")
	mockDB.AssertExpectations(t)
}

func TestCreateAppShouldGeneratePrivateKey(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, _, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	expected := &persistence.App{
		ID:            persistence.AppID{"the new app id"},
		Name:          "the new app name",
		MaxAccounts:   99,
		AllowedOrigin: "new app's origin",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	service := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{},
		App:     persistence.App{ID: ctxApp.ID},
	})
	mockDB.On("SaveApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.MatchedBy(func(privKey rsa.PrivateKey) bool {
		return privKey.Validate() == nil
	})).Return(expected, nil).Once()
	res, err := service.CreateApp(AppCreation{}, nil)

	mockDB.AssertExpectations(t)
	assert.Nil(err, "Expected nil error")
	assert.NotNil(res, "Expected non-nil app")
	assert.Equal(res, expected, "Received unexpected app")
}

func TestCreateAppShouldReturnSavedApp(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, _, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	expected := &persistence.App{
		ID:            persistence.AppID{"the new app id"},
		Name:          "the new app name",
		MaxAccounts:   99,
		AllowedOrigin: "new app's origin",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	service := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{},
		App:     persistence.App{ID: ctxApp.ID},
	})
	mockDB.On("SaveApp", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(expected, nil)
	res, err := service.CreateApp(AppCreation{}, nil)

	assert.Nil(err, "Expected nil error")
	assert.NotNil(res, "Expected non-nil app")
	assert.Equal(res, expected, "Received unexpected app")
	mockDB.AssertExpectations(t)
}

func TestNewAuthCtxReturnsAuthCtx(t *testing.T) {
	assert := assert.NewAssert(t)

	res := NewAppService(nil).NewAuthCtx(Authentication{})

	assert.NotNil(res, "AuthCtx should never be nil")
}

func TestGetAppsReturnsEmptyListIfUserIsNotAdmin(t *testing.T) {
	assert := assert.NewAssert(t)

	apps := NewAppService(nil).NewAuthCtx(Authentication{}).GetApps()

	assert.NotNil(apps, "Apps should never be nil")
	assert.Equal(len(apps), 0, "Apps slice is not empty")

}

func TestGetAppsReturnsContextAppIfItIsNotTheAdminApp(t *testing.T) {
	assert := assert.NewAssert(t)

	ctxApp := persistence.App{}
	apps := NewAppService(nil).NewAuthCtx(Authentication{
		Account: persistence.Account{
			Roles: []string{"admin"},
		},
		App: ctxApp,
	}).GetApps()

	assert.Equal(len(apps), 1, "Apps slice doesn't contain only one element")
	assert.Equal(apps[0].ID, ctxApp.ID, "Apps slice doesn't contain context app")

}

func TestGetAppsReturnsAllAppsInAdminAppForAdminUser(t *testing.T) {
	assert := assert.NewAssert(t)

	expected := []*persistence.App{
		&persistence.App{},
		&persistence.App{},
	}
	mockDB, _, _, _, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	mockDB.On("GetApps").Return(expected, nil)
	apps := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			Roles: []string{"admin"},
		},
		App: *ctxApp,
	}).GetApps()

	assert.Equal(len(apps), len(expected), "Apps slice doesn't contain expected number of apps")
	for idx, app := range apps {
		assert.Equal(app, expected[idx], "App in slice is not the one we expected")
	}

}

func TestGetAppsReturnsOnlyThoseAppsTheUserIsAdminOf(t *testing.T) {
	assert := assert.NewAssert(t)

	uid, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{uid}
	expected := []*persistence.App{
		&persistence.App{
			Admins: []persistence.AccountID{authAccountID},
		},
		&persistence.App{},
	}
	mockDB, _, _, _, ctxApp := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	mockDB.On("GetApps").Return(expected, nil)
	apps := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: authAccountID,
		},
		App: *ctxApp,
	}).GetApps()

	assert.Equal(len(apps), 1, "Apps slice doesn't contain expected number of apps")
	assert.Equal(apps[0], expected[0], "App in slice is not the one we expected")

}

func TestUpdateAppNameRejectsUpdateOfUnknownApp(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, _, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	updateAppID := persistence.AppID{"does not exist"}
	mockDB.On("GetApp", updateAppID).Once().Return(nil)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{}).UpdateAppName(updateAppID, AppName{"new name"})

	assert.NotNil(err, "Expected a non-nil error")
	assert.Equal(err, ErrAppDoesNotExist, "Expected a different error")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppNameRejectsUnauthenticatedUser(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{}).UpdateAppName(resApp.ID, AppName{"new name"})

	assert.NotNil(err, "Expected a non-nil error")
	assert.Equal(err, ErrAppUpdateForbidden, "Expected a different error")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppNameHandsOverPersistenceErrors(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{accountID},
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	mockDB.On("App", resApp.ID).Return(mockAppCtx)
	expected := fmt.Errorf("This did not work")
	mockAppCtx.On("UpdateAppName", "new name").Once().Return(expected)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).UpdateAppName(resApp.ID, AppName{"new name"})

	assert.NotNil(err, "Expected an error")
	assert.Equal(err, expected, "Expected a different error than I received")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppNameSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{accountID},
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	mockDB.On("App", resApp.ID).Return(mockAppCtx)
	mockAppCtx.On("UpdateAppName", "new name").Once().Return(nil)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).UpdateAppName(resApp.ID, AppName{"new name"})

	assert.Nil(err, "Expected no error")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppOriginRejectsUpdateOfUnknownApp(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, _, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	updateAppID := persistence.AppID{"does not exist"}
	mockDB.On("GetApp", updateAppID).Once().Return(nil)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{}).UpdateAppOrigin(updateAppID, AppOrigin{"new name"})

	assert.NotNil(err, "Expected a non-nil error")
	assert.Equal(err, ErrAppDoesNotExist, "Expected a different error")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppOriginRejectsUnauthenticatedUser(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, _, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{}).UpdateAppOrigin(resApp.ID, AppOrigin{"new origin"})

	assert.NotNil(err, "Expected a non-nil error")
	assert.Equal(err, ErrAppUpdateForbidden, "Expected a different error")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppOriginHandsOverPersistenceErrors(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{accountID},
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	mockDB.On("App", resApp.ID).Return(mockAppCtx)
	expected := fmt.Errorf("This did not work")
	mockAppCtx.On("UpdateAppOrigin", "new origin").Once().Return(expected)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).UpdateAppOrigin(resApp.ID, AppOrigin{"new origin"})

	assert.NotNil(err, "Expected an error")
	assert.Equal(err, expected, "Expected a different error than I received")
	mockDB.AssertExpectations(t)

}

func TestUpdateAppOriginSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	resApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{accountID},
	}
	mockDB.On("GetApp", resApp.ID).Return(resApp)
	mockDB.On("App", resApp.ID).Return(mockAppCtx)
	mockAppCtx.On("UpdateAppOrigin", "new origin").Once().Return(nil)
	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).UpdateAppOrigin(resApp.ID, AppOrigin{"new origin"})

	assert.Nil(err, "Expected no error")
	mockDB.AssertExpectations(t)

}

func TestDeleteAppFailsWhenAppDoesNotExist(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	targetApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{},
	}
	mockDB.On("GetApp", targetApp.ID).Return(nil)

	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).DeleteApp(targetApp.ID)

	assert.NotNil(err, "Expected error when deleting app")
	assert.Equal(ErrAppDoesNotExist, err, "Unexpected error when deleting app")
	mockDB.AssertExpectations(t)
}

func TestDeleteAppFailsWhenUserIsNotAdmin(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	targetApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{},
	}
	mockDB.On("GetApp", targetApp.ID).Return(targetApp)

	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).DeleteApp(targetApp.ID)

	assert.NotNil(err, "Expected error when deleting app")
	assert.Equal(ErrAppUpdateForbidden, err, "Unexpected error when deleting app")
	mockDB.AssertExpectations(t)
}

func TestDeleteAppSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, _, accountID, appID, _ := setupMocks(persistence.AppID{"0a791409-d58d-4175-ba02-2bdbdb8e6629"})
	targetApp := &persistence.App{
		ID:            appID,
		Name:          "App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        []persistence.AccountID{accountID},
	}
	mockDB.On("GetApp", targetApp.ID).Return(targetApp)
	mockDB.On("DeleteApp", targetApp.ID).Return(nil)

	err := NewAppService(mockDB).NewAuthCtx(Authentication{
		Account: persistence.Account{
			ID: accountID,
		},
	}).DeleteApp(targetApp.ID)

	assert.Nil(err, "Expected no error when deleting app")
	mockDB.AssertExpectations(t)
}

func TestAppCreationValidationSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	ac := AppCreation{
		Name:          "Name",
		MaxAccounts:   1,
		AllowedOrigin: "origin",
	}

	res := ac.Validate()

	assert.False(res.HasErrors(), "Expected no validation errors")
}

func TestAppCreationValidationFails(t *testing.T) {
	assert := assert.NewAssert(t)

	ac := AppCreation{
		Name:          "  ",
		MaxAccounts:   0,
		AllowedOrigin: "   ",
	}

	res := ac.Validate()

	assert.True(res.HasErrors(), "Expected no validation errors")
	assert.Equal(len(res.Errors), 3, "Unexpected number of validation errors")
}

func TestAppNameValidationSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	an := AppName{
		Name: "Name",
	}

	res := an.Validate()

	assert.False(res.HasErrors(), "Expected no validation errors")
}

func TestAppNameValidationFails(t *testing.T) {
	assert := assert.NewAssert(t)

	an := AppName{
		Name: "  ",
	}

	res := an.Validate()

	assert.True(res.HasErrors(), "Expected no validation errors")
	assert.Equal(len(res.Errors), 1, "Unexpected number of validation errors")
}

func TestAppOriginValidationSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	ao := AppOrigin{
		Origin: "Origin",
	}

	res := ao.Validate()

	assert.False(res.HasErrors(), "Expected no validation errors")
}

func TeotAppOriginValidationFails(t *testing.T) {
	assert := assert.NewAssert(t)

	ao := AppOrigin{
		Origin: "  ",
	}

	res := ao.Validate()

	assert.True(res.HasErrors(), "Expected no validation errors")
	assert.Equal(len(res.Errors), 1, "Unexpected number of validation errors")
}
