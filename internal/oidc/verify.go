package oidc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

func ParseAndVerifyIDToken(apiURL, token string) (*IDTokenClaims, error) {
	jwksURL, err := resolveJWKSURL(apiURL)
	if err != nil {
		return nil, err
	}
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch JWKS: %s", resp.Status)
	}
	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 {
		return nil, errors.New("no keys in JWKS")
	}
	pubKey, err := publicKeyFromJWK(jwks.Keys[0])
	if err != nil {
		return nil, err
	}
	var claims IDTokenClaims
	parser := jwt.NewParser(jwt.WithIssuer(resolveIssuer(apiURL)))
	_, err = parser.ParseWithClaims(token, &claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}
		return pubKey, nil
	})
	if err != nil {
		return nil, err
	}
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, errors.New("ID token is expired")
	}
	return &claims, nil
}

func publicKeyFromJWK(key jwkKey) (ed25519.PublicKey, error) {
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported JWK type %s/%s", key.Kty, key.Crv)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func resolveJWKSURL(apiURL string) (string, error) {
	base, err := url.Parse(strings.TrimRight(apiURL, "/"))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(&url.URL{Path: "/jwks"}).String(), nil
}

func resolveIssuer(apiURL string) string {
	base := strings.TrimRight(apiURL, "/")
	return base
}
