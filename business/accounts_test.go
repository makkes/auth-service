package business

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

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

func TestCreateAuthenticationTokenWithUnknownAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{"context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(nil)
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{"does not exist"}, "e", "p")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithInactiveAccount(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{"context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active: false,
	})
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{"does not exist"}, "e", "p")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithUnmatchedPassword(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{"context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	pwHash, _ := persistence.NewHash("pw1")
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active:       true,
		PasswordHash: pwHash,
	})
	as := NewAccountService(mockDB, nil)

	token, err := as.CreateAuthenticationToken(nil, persistence.AppID{"does not exist"}, "e", "pw2")

	assert.NotNil(err, "Expected non-nil error")
	assert.Equal(token, "", "Expected empty token")
}

func TestCreateAuthenticationTokenWithCorrectPassword(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, _ := setupMocks(persistence.AppID{"context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	pwHash, _ := persistence.NewHash("pw")
	mockAppCtx.On("GetAccountByEmail", mock.Anything).Return(&persistence.Account{
		Active:       true,
		PasswordHash: pwHash,
	})
	as := NewAccountService(mockDB, nil)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	token, err := as.CreateAuthenticationToken(privKey, persistence.AppID{"does not exist"}, "e", "pw")

	assert.Nil(err, "Expected nil error")
	assert.True(len(token) > 0, "Expected non-empty token")
}

func TestCreateAccountFailsWhenAccountAlreadyExists(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{"context app"})
	mockDB.On("App", mock.Anything).Return(mockAppCtx)
	mockAppCtx.On("GetAccountByEmail", "riker@startrek.io").Return(&persistence.Account{})
	as := NewAccountService(mockDB, nil)

	acc, err := as.NewAppContext(ctxApp).CreateAccount(AccountCreation{
		Email: "riker@startrek.io",
	})

	assert.Nil(acc, "Expected nil account")
	assert.Equal(err, EmailExistsError, "Expected an EmailExistsError")
	mockDB.AssertExpectations(t)
	mockAppCtx.AssertExpectations(t)

}

func TestCreateAccountReturnsActiveAccountDirectly(t *testing.T) {
	assert := assert.NewAssert(t)

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{"context app"})
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

	mockDB, mockAppCtx, _, _, ctxApp := setupMocks(persistence.AppID{"context app"})
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
