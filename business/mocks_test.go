package business

import (
	"crypto/rsa"

	"github.com/makkes/services.makk.es/auth/persistence"
	uuid "github.com/gofrs/uuid"
	"github.com/stretchr/testify/mock"
)

type MockDB struct {
	mock.Mock
}

func (m *MockDB) GetAccountID(activationToken string) *persistence.AccountID {
	args := m.Called(activationToken)
	return args.Get(0).(*persistence.AccountID)
}

func (m *MockDB) GetApp(appID persistence.AppID) *persistence.App {
	args := m.Called(appID)
	res := args.Get(0)
	if res == nil {
		return nil
	}
	return args.Get(0).(*persistence.App)
}

func (m *MockDB) App(appID persistence.AppID) persistence.AppContext {
	args := m.Called(appID)
	return args.Get(0).(persistence.AppContext)
}

func (m *MockDB) SaveApp(appID persistence.AppID, name string, maxAccounts int, allowedOrigin string, mailTemplates persistence.MailTemplates, admins []persistence.AccountID, privateKey rsa.PrivateKey) (*persistence.App, error) {
	args := m.Called(appID, name, maxAccounts, allowedOrigin, mailTemplates, admins, privateKey)
	arg0 := args.Get(0)
	if arg0 == nil {
		return nil, args.Error(1)
	}
	return arg0.(*persistence.App), args.Error(1)
}

func (m *MockDB) DeleteApp(appID persistence.AppID) error {
	args := m.Called(appID)
	arg0 := args.Get(0)
	if arg0 == nil {
		return nil
	}
	return arg0.(error)
}

func (m *MockDB) GetApps() []*persistence.App {
	args := m.Called()
	return args.Get(0).([]*persistence.App)
}

type MockAppCtx struct {
	mock.Mock
}

func (m *MockAppCtx) GetAccount(id persistence.AccountID) *persistence.Account {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*persistence.Account)
}

func (m *MockAppCtx) GetAccountByEmail(email string) *persistence.Account {
	args := m.Called(email)
	account := args.Get(0)
	if account == nil {
		return nil
	}
	return account.(*persistence.Account)
}

func (m *MockAppCtx) GetAccounts() []*persistence.Account {
	args := m.Called()
	return args.Get(0).([]*persistence.Account)
}

func (m *MockAppCtx) SaveAccount(account persistence.Account) {
	m.Called(account)
}

func (m *MockAppCtx) SaveActivationToken(accountID persistence.AccountID, token string) error {
	args := m.Called(accountID, token)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

func (m *MockAppCtx) GetActivationToken(id persistence.AccountID) string {
	args := m.Called()
	return args.Get(0).(string)
}

func (m *MockAppCtx) DeleteActivationToken(id persistence.AccountID) error {
	return nil
}

func (m *MockAppCtx) UpdateAppName(newName string) error {
	args := m.Called(newName)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

func (m *MockAppCtx) UpdateAppOrigin(newOrigin string) error {
	args := m.Called(newOrigin)
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(error)
}

type MockMailer struct {
	mock.Mock
}

func mockMailer() *MockMailer {
	return new(MockMailer)
}

func (m *MockMailer) SendActivationMail(to string, token string, id persistence.AccountID, tmpl string) error {
	args := m.Called(to, token, id, tmpl)
	return args.Error(0)
}

func setupMocks(ctxAppID persistence.AppID) (*MockDB, *MockAppCtx, persistence.AccountID, persistence.AppID, *persistence.App) {
	mockDB := new(MockDB)
	uuid, _ := uuid.NewV4()
	accountID, _ := persistence.NewAccountID(uuid.String())
	appID, _ := persistence.NewAppID("requested app id")
	ctxApp := &persistence.App{
		ID:            ctxAppID,
		Name:          "Ctx App Name",
		MaxAccounts:   0,
		AllowedOrigin: "",
		MailTemplates: persistence.MailTemplates{},
		Admins:        nil,
	}
	mockAppCtx := new(MockAppCtx)
	return mockDB, mockAppCtx, accountID, appID, ctxApp
}
