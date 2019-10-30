package business

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"golang.org/x/xerrors"

	"github.com/gofrs/uuid"

	"github.com/makkes/assert"
	"github.com/makkes/services.makk.es/auth/persistence"
	"github.com/stretchr/testify/mock"
)

func TestAccountCreationValidationSucceeds(t *testing.T) {
	assert := assert.NewAssert(t)

	ac := AccountCreation{
		Email:    "email",
		Password: "password",
	}

	res := ac.Validate()

	assert.False(res.HasErrors(), "Expected no validation errors")

}

func TestAccountCreationValidationFails(t *testing.T) {
	assert := assert.NewAssert(t)

	ac := AccountCreation{
		Email: "  ",
		Password: "	",
	}

	res := ac.Validate()

	assert.True(res.HasErrors(), "Expected no validation errors")
	assert.Equal(len(res.Errors), 2, "Unexpected number of validation errors")
}

func TestNewAccountServiceReturnsService(t *testing.T) {
	assert := assert.NewAssert(t)

	as := NewAccountService(nil, nil)

	assert.NotNil(as, "Expeccted non-nil AccountService")
}

func TestNewAppContextReturnsCtx(t *testing.T) {
	assert := assert.NewAssert(t)

	ctx := NewAccountService(nil, nil).NewAppContext(nil)

	assert.NotNil(ctx, "Expeccted non-nil AppContext")

}

func TestRefreshAuthenticationTokenWithUnknownAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", mock.Anything).Return(nil)
	as := NewAccountService(mockDB, nil)

	token, err := as.RefreshAuthenticationToken(nil, persistence.AppID{ID: "any app"}, persistence.AccountID{})

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestRefreshAuthenticationTokenWithInactiveAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", mock.Anything).Return(&persistence.Account{
		Active: false,
	})
	as := NewAccountService(mockDB, nil)

	token, err := as.RefreshAuthenticationToken(nil, persistence.AppID{ID: "any app"}, persistence.AccountID{})

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestRefreshAuthenticationToken(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", mock.Anything).Return(&persistence.Account{
		Active: true,
	})
	as := NewAccountService(mockDB, nil)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token, err := as.RefreshAuthenticationToken(privKey, persistence.AppID{ID: "does not exist"}, persistence.AccountID{})

	assert.Nil(err, "Expected nil error")
	assert.True(len(token) > 0, "Expected non-empty token")
}

func TestCreateAuthenticationTokenWithUnknownAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(nil)
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{ID: "does not exist"}, "e", "p")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithInactiveAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active: false,
	})
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{ID: "does not exist"}, "e", "p")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithUnmatchedPassword(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	pwHash, _ := persistence.NewHash("pw1")
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active:       true,
		PasswordHash: pwHash,
	})
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{ID: "does not exist"}, "e", "pw2")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithCorrectPassword(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	pwHash, _ := persistence.NewHash("pw")
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active:       true,
		PasswordHash: pwHash,
	})
	as := NewAccountService(mockDB, nil)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token, err := as.CreateAuthenticationToken(privKey, persistence.AppID{ID: "does not exist"}, "e", "pw")

	assert.Nil(err, "Expected nil error")
	assert.True(len(token) > 0, "Expected non-empty token")
}

func TestCreateAccountFailsWhenAccountCannotBePersisted(t *testing.T) {
	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(nil)
	mockAppCtx.On("SaveAccount", mock.Anything).Return(xerrors.New("persistence is broken"))
	as := NewAccountService(mockDB, nil)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email: "riker@startrek.io",
	})

	assert := assert.NewAssert(t)
	assert.Nil(acc, "Expected nil account")
	assert.NotNil(err, "Expected non-nil error")
}

func TestCreateAccountFailsWhenTokenCannotBePersisted(t *testing.T) {
	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(nil)
	mockAppCtx.On("SaveAccount", mock.Anything)
	mockAppCtx.On("SaveActivationToken", mock.Anything, mock.Anything).Return(xerrors.New("cannot save token"))
	as := NewAccountService(mockDB, nil)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email: "riker@startrek.io",
	})

	assert := assert.NewAssert(t)
	assert.Nil(acc, "Expected nil account")
	assert.NotNil(err, "Expected non-nil error")
}

func TestCreateAccountFailsWhenAccountAlreadyExists(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(&persistence.Account{Active: true})
	as := NewAccountService(mockDB, nil)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email: "riker@startrek.io",
	})

	assert.Nil(acc, "Expected nil account")
	assert.Equal(err, EmailExistsError, "Expected an EmailExistsError")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)

}

func TestCreateAccountSucceedsWhenAccountExistsButIsNotActivated(t *testing.T) {
	assert := assert.NewAssert(t)

	existingID := uuid.FromStringOrNil("9738155e-208a-4b5b-ba53-a2fab36510c3")
	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(
		&persistence.Account{
			Active: false,
			ID:     persistence.AccountID{UUID: existingID},
		})
	mockAppCtx.On("SaveAccount", mock.MatchedBy(func(acc persistence.Account) bool {
		return acc.ID.UUID == existingID
	}))
	mockAppCtx.On("SaveActivationToken", mock.AnythingOfType("persistence.AccountID"), mock.AnythingOfType("string")).Return(nil)
	mockMailer := mockMailer()
	mockMailer.On("SendActivationMail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	as := NewAccountService(mockDB, mockMailer)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email: "riker@startrek.io",
	})

	assert.NotNil(acc, "Expected non-nil account")
	assert.Nil(err, "Expected nil error")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)

}

func TestCreateAccountReturnsActiveAccountDirectly(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(nil)
	mockAppCtx.On("SaveAccount", mock.AnythingOfType("persistence.Account"))
	as := NewAccountService(mockDB, nil)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email:    "riker@startrek.io",
		Password: "deanna",
		Active:   true,
	})

	assert.NotNil(acc, "Expected non-nil account")
	assert.Equal(len(acc.ID.String()), 36, "Account ID is not of expected length")
	assert.Equal(len(acc.Roles), 0, "Expected account to have no roles")
	assert.Equal(acc.Email, "riker@startrek.io", "Expected account to have another email address")
	assert.True(len(acc.PasswordHash.Salt) > 0, "Password salt is of unexpected length")
	assert.True(acc.PasswordHash.Iter > 0, "Expected more iterations in password hash")
	assert.True(len(acc.PasswordHash.Hash) > 0, "Expected password hash to be longer")
	assert.True(acc.PasswordHash.Matches("deanna"), "Expected another password")
	assert.True(acc.Active, "Expected account to be active")
	assert.Nil(err, "Expected nil error")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)
}

func TestCreateAccountSendsActivationTokenAndReturnsAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(nil)
	mockAppCtx.On("SaveAccount", mock.AnythingOfType("persistence.Account"))
	mockAppCtx.On("SaveActivationToken", mock.AnythingOfType("persistence.AccountID"), mock.AnythingOfType("string")).Return(nil)
	mockMailer := mockMailer()
	mockMailer.On("SendActivationMail", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	as := NewAccountService(mockDB, mockMailer)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email:    "riker@startrek.io",
		Password: "raika",
	})

	assert.NotNil(acc, "Expected non-nil account")
	assert.Nil(err, "Expected nil error")
	assert.Equal(len(acc.ID.String()), 36, "Account ID is not of expected length")
	assert.Equal(len(acc.Roles), 0, "Expected account to have no roles")
	assert.Equal(acc.Email, "riker@startrek.io", "Expected account to have another email address")
	assert.True(len(acc.PasswordHash.Salt) > 0, "Password salt is of unexpected length")
	assert.True(acc.PasswordHash.Iter > 0, "Expected more iterations in password hash")
	assert.True(len(acc.PasswordHash.Hash) > 0, "Expected password hash to be longer")
	assert.True(acc.PasswordHash.Matches("raika"), "Expected another password")
	assert.False(acc.Active, "Expected account to be active")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)
	mockMailer.AssertExpectations(t)
}

func TestGetAccountWithUnknownAuthenticatedUserReturnsNil(t *testing.T) {
	mockDB, mockAppCtx, _, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	authAccountUUID, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{UUID: authAccountUUID}
	mockAppCtx.On("GetAccount", authAccountID).Return(nil)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, authAccountID, persistence.AccountID{})

	assert := assert.NewAssert(t)
	assert.Nil(account, "Expected nil account")
}

func TestGetAccountWithUnknownUserReturnsNil(t *testing.T) {
	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	authAccountUUID, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{UUID: authAccountUUID}
	authAccount := persistence.Account{ID: authAccountID}
	mockAppCtx.On("GetAccount", authAccountID).Return(&authAccount)
	mockAppCtx.On("GetAccount", accountID).Return(nil)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, authAccountID, accountID)

	assert := assert.NewAssert(t)
	assert.Nil(account, "Expected nil account")
}

func TestGetAccountWithDifferentUserReturnsNil(t *testing.T) {
	mockDB, mockAppCtx, _, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	authAccountUUID, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{UUID: authAccountUUID}
	authAccount := persistence.Account{ID: authAccountID}
	mockAppCtx.On("GetAccount", authAccountID).Return(&authAccount)
	differentAccountUUID, _ := uuid.NewV4()
	differentAccountID := persistence.AccountID{UUID: differentAccountUUID}
	differentAccount := persistence.Account{ID: differentAccountID, Active: true}
	mockAppCtx.On("GetAccount", differentAccountID).Return(&differentAccount)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, authAccountID, differentAccountID)

	assert := assert.NewAssert(t)
	assert.Nil(account, "Expected nil account")
}

func TestGetAccountWithDifferentUserThatIsAdminButInactiveReturnsNil(t *testing.T) {
	mockDB, mockAppCtx, _, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	authAccountUUID, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{UUID: authAccountUUID}
	authAccount := persistence.Account{ID: authAccountID, Active: false, Roles: persistence.Roles{"admin"}}
	mockAppCtx.On("GetAccount", authAccountID).Return(&authAccount)
	differentAccountUUID, _ := uuid.NewV4()
	differentAccountID := persistence.AccountID{UUID: differentAccountUUID}
	differentAccount := persistence.Account{ID: differentAccountID, Active: true}
	mockAppCtx.On("GetAccount", differentAccountID).Return(&differentAccount)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, authAccountID, differentAccountID)

	assert := assert.NewAssert(t)
	assert.Nil(account, "Expected nil account")
}

func TestDeleteAccount(t *testing.T) {
	type test struct {
		name           string
		authAccount    *persistence.Account
		account        *persistence.Account
		id             persistence.AccountID
		deletionResult error
		out            error
	}
	accountUUID, _ := uuid.NewV4()
	deletionResult := fmt.Errorf("this is the deletion result")
	tests := []test{
		{
			name:        "unknown authorized user",
			authAccount: nil,
			id:          persistence.AccountID{UUID: accountUUID},
			out:         DeletionForbiddenError,
		},
		{
			name:        "inactive authorized user",
			authAccount: &persistence.Account{Active: false},
			id:          persistence.AccountID{UUID: accountUUID},
			out:         DeletionForbiddenError,
		},
		{
			name:        "unknown account",
			authAccount: &persistence.Account{Active: true},
			account:     nil,
			id:          persistence.AccountID{UUID: accountUUID},
			out:         DeletionForbiddenError,
		},
		{
			name:        "non-admin authorized user",
			authAccount: &persistence.Account{Active: true, Roles: nil},
			account:     &persistence.Account{Active: true},
			id:          persistence.AccountID{UUID: accountUUID},
			out:         DeletionForbiddenError,
		},
		{
			name:           "admin authorized user",
			authAccount:    &persistence.Account{Active: true, Roles: persistence.Roles{"admin"}},
			account:        &persistence.Account{Active: true},
			id:             persistence.AccountID{UUID: accountUUID},
			deletionResult: deletionResult,
			out:            deletionResult,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.NewAssert(t)
			mockDB, mockAppCtx, _, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
			mockDB.On("App", mock.Anything).Return(mockAppCtx)
			authAccountUUID, _ := uuid.NewV4()
			authAccountID := persistence.AccountID{UUID: authAccountUUID}
			mockAppCtx.On("GetAccount", authAccountID).Return(tt.authAccount)
			mockAppCtx.On("GetAccount", tt.id).Return(tt.account)
			mockAppCtx.On("DeleteAccount", tt.id).Return(tt.deletionResult)
			as := NewAccountService(mockDB, nil)
			err := as.DeleteAccount(appID, authAccountID, tt.id)
			assert.Equal(err, tt.out, "Got unexpected error")
		})
	}
}

func TestGetAccountWithDifferentUserThatIsAdminReturnsAccount(t *testing.T) {
	mockDB, mockAppCtx, _, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	authAccountUUID, _ := uuid.NewV4()
	authAccountID := persistence.AccountID{UUID: authAccountUUID}
	authAccount := persistence.Account{ID: authAccountID, Active: true, Roles: persistence.Roles{"admin"}}
	mockAppCtx.On("GetAccount", authAccountID).Return(&authAccount)
	differentAccountUUID, _ := uuid.NewV4()
	differentAccountID := persistence.AccountID{UUID: differentAccountUUID}
	differentAccount := persistence.Account{ID: differentAccountID, Active: true}
	mockAppCtx.On("GetAccount", differentAccountID).Return(&differentAccount)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, authAccountID, differentAccountID)

	assert := assert.NewAssert(t)
	assert.NotNil(account, "Expected non-nil account")
	assert.Equal(account, &differentAccount, "Expected different account")
}

func TestGetAccountWithInactiveUserReturnsNil(t *testing.T) {
	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	inactiveAccount := persistence.Account{ID: accountID, Active: false}
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", accountID).Return(&inactiveAccount)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, accountID, accountID)

	assert := assert.NewAssert(t)
	assert.Nil(account, "Expected nil account")
}

func TestGetAccountWithActiveUserReturnsAccount(t *testing.T) {
	mockDB, mockAppCtx, accountID, appID, _ := setupMocks(persistence.AppID{ID: "context app"})
	activeAccount := persistence.Account{
		ID:        accountID,
		Active:    true,
		Email:     "user@example.org",
		Roles:     persistence.Roles{"editor", "user"},
		UpdatedAt: time.Now(),
	}
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccount", accountID).Return(&activeAccount)
	as := NewAccountService(mockDB, nil)

	account := as.GetAccount(appID, accountID, accountID)

	assert := assert.NewAssert(t)
	assert.NotNil(account, "Expected non-nil account")
	assert.Equal(account, &activeAccount, "Expected another account")
}
