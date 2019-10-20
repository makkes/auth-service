package utils

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/makkes/services.makk.es/auth/persistence"
)

const (
	tokenExpiration    = 87600 * time.Hour
	refreshGracePeriod = 5 * time.Minute
)

func CreateJWT(key *rsa.PrivateKey, account persistence.AccountID, app persistence.AppID, now time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
		Issuer:    app.String(),
		Subject:   account.String(),
		ExpiresAt: now.Add(tokenExpiration).Unix(),
	})

	return token.SignedString(key)
}

func ParseJWT(in string, key crypto.PublicKey, checkTokenExpiration bool, now time.Time) (*jwt.StandardClaims, error) {
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
					if checkTokenExpiration || now.Sub(time.Unix(claims.ExpiresAt, 0)) > refreshGracePeriod {
						return claims, valErr
					}
					return claims, nil
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
