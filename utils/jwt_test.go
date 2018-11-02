package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/makkes/assert"
	"github.com/makkes/services.makk.es/auth/persistence"
	uuid "github.com/satori/go.uuid"
)

func randomAccountID() persistence.AccountID {
	uuid, err := uuid.NewV4()
	if err != nil {
		panic("Could not generate account ID")
	}
	return persistence.AccountID{UUID: uuid}
}

func randomAppID() persistence.AppID {
	return persistence.AppID{ID: "app ID"}
}

func TestJWTCreation(t *testing.T) {
	assert := assert.NewAssert(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, fmt.Sprintf("Error creating private key: %s", err))
	jwt, err := CreateJWT(privKey, randomAccountID(), randomAppID(), time.Now())

	assert.Nil(err, fmt.Sprintf("Unexpected error: %s", err))
	assert.True(len(jwt) > 0, "JWT is empty")
}

func TestJWTParsingAnInvalidToken(t *testing.T) {
	assert := assert.NewAssert(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, fmt.Sprintf("Error creating private key: %s", err))

	claims, err := ParseJWT("not a JWT", privKey.Public())

	assert.NotNil(err, fmt.Sprintf("Expected an error"))
	assert.Nil(claims, "Expected nil claims for invalid JWT")
}

func TestJWTParsingATokenWithAnInvalidSignatureAlg(t *testing.T) {
	assert := assert.NewAssert(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, fmt.Sprintf("Error creating private key: %s", err))

	claims, err := ParseJWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", privKey.Public())

	assert.NotNil(err, fmt.Sprintf("Expected an error"))
	assert.Nil(claims, "Expected nil claims for invalid JWT")
}

func TestJWTCreationAndParsing(t *testing.T) {
	assert := assert.NewAssert(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, fmt.Sprintf("Error creating private key: %s", err))
	appID := randomAppID()
	accID := randomAccountID()
	now := time.Now()
	jwt, _ := CreateJWT(privKey, accID, appID, now)

	claims, err := ParseJWT(jwt, privKey.Public())

	assert.Nil(err, fmt.Sprintf("Unexpected error: %s", err))
	assert.Equal(claims.Issuer, appID.String(), "Unexpected issuer in JWT")
	assert.Equal(claims.Subject, accID.String(), "Unexpected subject in JWT")
	assert.Equal(claims.ExpiresAt, now.Add(87600*time.Hour).Unix(), "Unexpected exp in JWT")
}

func TestJWTParsingAnExpiredToken(t *testing.T) {
	assert := assert.NewAssert(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.Nil(err, fmt.Sprintf("Error creating private key: %s", err))
	appID := randomAppID()
	accID := randomAccountID()
	now := time.Now().Add(-87600 * time.Hour).Add(-1 * time.Second)
	jwtString, _ := CreateJWT(privKey, accID, appID, now)

	claims, err := ParseJWT(jwtString, privKey.Public())

	assert.NotNil(claims, "Expected to get a claims struct")
	assert.NotNil(err, "Expected an error denoting the token is expired")
	valErr, ok := err.(*jwt.ValidationError)
	assert.True(ok, "Expected a ValidationError denoting the token is expired")
	assert.True(valErr.Errors&jwt.ValidationErrorExpired != 0, "Expected an error code denoting the token is expired")
}
