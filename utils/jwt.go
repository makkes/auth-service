package utils

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/makkes/services.makk.es/auth/persistence"
)

func CreateJWT(key *rsa.PrivateKey, account persistence.AccountID, app persistence.AppID, now time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Issuer:    app.String(),
		Subject:   account.String(),
		ExpiresAt: now.Add(87600 * time.Hour).Unix(),
	})

	return token.SignedString(key)
}

func ParseJWT(in string, key crypto.PublicKey) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(in, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if token == nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok {
		if err != nil {
			if valErr, ok := err.(*jwt.ValidationError); ok {
				if valErr.Errors&jwt.ValidationErrorExpired != 0 {
					return claims, valErr
				}
			}
			return nil, fmt.Errorf("No valid token found: %s", err)
		}

		if token.Valid {
			return claims, nil
		} else {
			return nil, fmt.Errorf("No valid token found")
		}
	} else {
		return nil, fmt.Errorf("Token claims could not be asserted to be of type jwt.StandardClaims")
	}
}
