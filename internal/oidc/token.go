package oidc

import (
	"crypto/ed25519"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type IDTokenClaims struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	Nonce  string   `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

func NewIDToken(issuer, subject, email string, groups []string, nonce string, key ed25519.PrivateKey, kid string) (string, error) {
	claims := IDTokenClaims{
		Email:  email,
		Groups: groups,
		Nonce:  nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			ID:        subject + ":" + time.Now().Format("20060102150405"),
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if kid != "" {
		jwtToken.Header["kid"] = kid
	}
	return jwtToken.SignedString(key)
}
