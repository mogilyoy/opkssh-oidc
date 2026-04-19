package sshcert

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mastervolkov/opkssh-oidc/internal/oidc"
	"golang.org/x/crypto/ssh"
)

type VerifyResult struct {
	Username string
	Groups   []string
	Sudo     bool
}

func EnsureCA(caPath string) error {
	if _, err := os.Stat(caPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", caPath, "-N", "", "-q")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func EnsureUserKeyPair(username, privPath string) error {
	if _, err := os.Stat(privPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-f", privPath, "-N", "", "-q", "-C", fmt.Sprintf("%s@qwe", username))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func CreateCertificate(username, idToken, pubKeyPath, certPath, caKeyPath string) error {
	pubBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return err
	}

	caBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(caBytes)
	if err != nil {
		return err
	}

	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           username,
		ValidPrincipals: []string{username},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(15 * time.Minute).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"oidc-id-token": idToken,
			},
		},
	}

	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return err
	}

	data := ssh.MarshalAuthorizedKey(cert)
	if err := os.WriteFile(certPath, data, 0o644); err != nil {
		return err
	}
	return nil
}

func VerifyCertificate(certPath, caPubPath, apiURL string) (*VerifyResult, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("certificate file does not contain an SSH certificate")
	}
	caData, err := os.ReadFile(caPubPath)
	if err != nil {
		return nil, err
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey(caData)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caKey.Marshal()) {
		return nil, errors.New("certificate signature key does not match CA public key")
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return bytes.Equal(auth.Marshal(), caKey.Marshal())
		},
	}
	if err := checker.CheckCert(cert.KeyId, cert); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}
	if time.Now().Unix() < int64(cert.ValidAfter) || time.Now().Unix() > int64(cert.ValidBefore) {
		return nil, errors.New("certificate is not currently valid")
	}
	idToken, ok := cert.Extensions["oidc-id-token"]
	if !ok {
		return nil, errors.New("OIDC token extension not found in certificate")
	}
	claims, err := oidc.ParseAndVerifyIDToken(apiURL, idToken)
	if err != nil {
		return nil, err
	}
	result := &VerifyResult{Username: claims.Subject, Groups: claims.Groups, Sudo: hasSudo(claims.Groups)}
	return result, nil
}

func hasSudo(groups []string) bool {
	for _, g := range groups {
		if strings.Contains(g, "admin") || strings.Contains(g, "sudo") {
			return true
		}
	}
	return false
}
