package persistence

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gofrs/uuid"
	log "github.com/makkes/golib/logging"
	"golang.org/x/crypto/pbkdf2"
)

type AccountID struct {
	uuid.UUID
}

func (id AccountID) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.S = aws.String("account:" + id.UUID.String())
	return nil
}

func (id *AccountID) UnmarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	if av.S == nil {
		return nil
	}
	idArr := strings.Split(*av.S, ":")
	if len(idArr) != 2 || idArr[0] != "account" {
		log.Info("Could not parse account ID %s", *av.S)
		return fmt.Errorf("Error parsing account ID %s", *av.S)
	}
	uid, err := uuid.FromString(idArr[1])
	if err != nil {
		log.Info("Could not parse account ID %s: %s", idArr[1], err)
		return err
	}
	id.UUID = uid
	return nil
}

type Hash struct {
	Hash []byte
	Iter int
	Salt []byte
}

// Scan makes Hash implement the sql.Scanner interface
func (h *Hash) Scan(src interface{}) error {
	encodedHash, ok := src.(string)
	if !ok {
		return xerrors.Errorf("%#v is not a string", src)
	}
	err := json.Unmarshal([]byte(encodedHash), h)
	if err != nil {
		return xerrors.Errorf("could not unmarshal password hash %s: %w", encodedHash, err)
	}

	return nil
}

// Value makes Hash implement the sql.driver.Scanner interface
func (r Hash) Value() (driver.Value, error) {
	encodedHash, err := json.Marshal(r)
	if err != nil {
		return nil, xerrors.Errorf("could not marshal password hash: %w", err)
	}

	return driver.Value(encodedHash), nil
}

func NewHash(in string) (Hash, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return Hash{}, err
	}
	iter := 40000
	return Hash{generateHash(salt, iter, in), iter, salt}, nil
}

func generateHash(salt []byte, iter int, in string) []byte {
	return pbkdf2.Key([]byte(in), salt, iter, 32, sha256.New)
}

func (h Hash) Matches(password string) bool {
	h2 := generateHash(h.Salt, h.Iter, password)
	if len(h.Hash) != len(h2) {
		return false
	}

	for idx := range h.Hash {
		if h.Hash[idx] != h2[idx] {
			return false
		}
	}
	return true
}

type Roles []string

// Scan makes Roles implement the sql.Scanner interface
func (r *Roles) Scan(src interface{}) error {
	encodedRoles, ok := src.(string)
	if !ok {
		return xerrors.Errorf("%#v is not a string", src)
	}
	err := json.Unmarshal([]byte(encodedRoles), r)
	if err != nil {
		return xerrors.Errorf("could not unmarshal roles %s: %w", encodedRoles, err)
	}

	return nil
}

// Value makes Roles implement the sql.driver.Scanner interface
func (r Roles) Value() (driver.Value, error) {
	encodedRoles, err := json.Marshal(r)
	if err != nil {
		return nil, xerrors.Errorf("could not marshal roles: %w", err)
	}

	return driver.Value(encodedRoles), nil
}

type Account struct {
	ID           AccountID `json:"id" dynamodbav:"subID"`
	Email        string    `json:"email"`
	Roles        Roles     `json:"roles"`
	PasswordHash Hash      `json:"-" dynamodbav:"passwordHash"`
	Active       bool
}

type AppID struct {
	ID string
}

func (id AppID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.ID)
}

func (id AppID) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.S = aws.String(id.ID)
	return nil
}

func (id *AppID) UnmarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	if av.S == nil {
		return nil
	}
	id.ID = *av.S
	return nil
}

type MailTemplates struct {
	ActivateAccount string `json:"activateAccount"`
}

// Scan makes MailTemplates implement the sql.Scanner interface
func (m *MailTemplates) Scan(src interface{}) error {
	encodedMailTemplates, ok := src.(string)
	if !ok {
		return xerrors.Errorf("%#v is not a string", src)
	}
	err := json.Unmarshal([]byte(encodedMailTemplates), m)
	if err != nil {
		return xerrors.Errorf("could not unmarshal mail templates %s: %w", encodedMailTemplates, err)
	}

	return nil
}

// Value makes MailTemplates implement the sql.driver.Scanner interface
func (m MailTemplates) Value() (driver.Value, error) {
	encodedMailTemplates, err := json.Marshal(m)
	if err != nil {
		return nil, xerrors.Errorf("could not marshal mail templates: %w", err)
	}

	return driver.Value(encodedMailTemplates), nil
}

type AppKey struct {
	Key rsa.PrivateKey
}

// Scan makes AppKey implement the sql.Scanner interface
func (k *AppKey) Scan(src interface{}) error {
	encodedPrivateKey, ok := src.(string)
	if !ok {
		return xerrors.Errorf("%#v is not a string", src)
	}
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(encodedPrivateKey)
	if err != nil {
		return xerrors.Errorf("could not decode private key '%#v': %s", encodedPrivateKey, err)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(decodedPrivateKey)
	if err != nil {
		return xerrors.Errorf("could not parse private key '%#v': %s", decodedPrivateKey, err)
	}
	k.Key = *privateKey

	return nil
}

// Value makes AppKey implement the sql.driver.Scanner interface
func (k AppKey) Value() (driver.Value, error) {
	return driver.Value(base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(&k.Key))), nil
}

func (key AppKey) EncodePublicKey() string {
	pubASN1, err := x509.MarshalPKIXPublicKey(&key.Key.PublicKey)
	if err != nil {
		log.Error("Error encoding public key: %s", err)
		return ""
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM)
}

func (key AppKey) MarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	av.B = x509.MarshalPKCS1PrivateKey(&key.Key)
	return nil
}

func (key *AppKey) UnmarshalDynamoDBAttributeValue(av *dynamodb.AttributeValue) error {
	if av.B == nil {
		return nil
	}
	parsedKey, err := x509.ParsePKCS1PrivateKey(av.B)
	if err != nil {
		return err
	}
	key.Key = *parsedKey
	return nil
}

type AppAdmins []AccountID

// Scan makes AppAdmins implement the sql.Scanner interface
func (a *AppAdmins) Scan(src interface{}) error {
	encodedAppAdmins, ok := src.(string)
	if !ok {
		return xerrors.Errorf("%#v is not a string", src)
	}
	err := json.Unmarshal([]byte(encodedAppAdmins), a)
	if err != nil {
		return xerrors.Errorf("could not unmarshal roles %s: %w", encodedAppAdmins, err)
	}

	return nil
}

// Value makes AppAdmins implement the sql.driver.Scanner interface
func (a AppAdmins) Value() (driver.Value, error) {
	encodedAppAdmins, err := json.Marshal(a)
	if err != nil {
		return nil, xerrors.Errorf("could not marshal app admins: %w", err)
	}

	return driver.Value(encodedAppAdmins), nil
}

type App struct {
	ID            AppID         `json:"id" dynamodbav:"appID"`
	Name          string        `json:"name"`
	MaxAccounts   int           `json:"maxAccounts"`
	AllowedOrigin string        `json:"allowedOrigin"`
	MailTemplates MailTemplates `json:"mailTemplates"`
	Admins        AppAdmins     `json:"admins"`
	PrivateKey    AppKey        `json:"-" dynamodbav:"privateKey"`
	PublicKey     string        `json:"publicKey" dynamodbav:"-"`
}

func (id AppID) String() string {
	return id.ID
}

func NewAppID(id string) (AppID, error) {
	return AppID{id}, nil
}

func (acc Account) String() string {
	return fmt.Sprintf("id:%s email:%s password:%v active:%t roles:%s", acc.ID.String(), acc.Email, acc.PasswordHash, acc.Active, acc.Roles)
}

func (acc Account) HasRole(hasRole string) bool {
	for _, role := range acc.Roles {
		if role == hasRole {
			return true
		}
	}
	return false
}

func NewAccountID(id string) (AccountID, error) {
	accountID := AccountID{}
	accountUUID, err := uuid.FromString(id)
	if err != nil {
		return accountID, err
	}

	accountID.UUID = accountUUID
	return accountID, nil
}

type DB interface {
	GetApp(appID AppID) *App
	App(appID AppID) AppContext
	SaveApp(id AppID, name string, maxAccounts int, allowedOrigin string, mailTemplates MailTemplates, admins AppAdmins, privateKey rsa.PrivateKey) (*App, error)
	DeleteApp(id AppID) error
	GetApps() []*App
}

type AppContext interface {
	SaveActivationToken(accountID AccountID, token string) error
	GetAccountByEmail(email string) *Account
	GetActivationToken(id AccountID) string
	DeleteActivationToken(id AccountID) error
	SaveAccount(account Account) error
	GetAccount(id AccountID) *Account
	GetAccounts() []*Account
	DeleteAccount(id AccountID) error
	UpdateAppName(newName string) error
	UpdateAppOrigin(newOrigin string) error
}

func (a AccountID) String() string {
	return a.UUID.String()
}
