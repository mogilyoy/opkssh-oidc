package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mastervolkov/opkssh-oidc/internal/api"
	ss "github.com/mastervolkov/opkssh-oidc/internal/ssh"
	"github.com/spf13/cobra"
)

type storedToken struct {
	Username    string    `json:"username"`
	AccessToken string    `json:"access_token"`
	IDToken     string    `json:"id_token"`
	Expiry      time.Time `json:"expiry"`
}

var (
	apiURL  string
	dataDir string
)

func main() {
	rootCmd := &cobra.Command{Use: "qwe", Short: "Prototype OIDC + SSH client"}
	rootCmd.PersistentFlags().StringVar(&apiURL, "api-url", "http://127.0.0.1:8080", "local OIDC API URL")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "qwe data directory (default ~/.qwe)")

	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(sshCmd())
	rootCmd.AddCommand(verifyCmd())
	rootCmd.AddCommand(authKeysCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func resolveDataDir() (string, error) {
	if dataDir != "" {
		return dataDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".qwe"), nil
}

func writeJSON(path string, v any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func requestToken(ctx context.Context, apiURL, username string) (*storedToken, error) {
	reqBody := map[string]string{"username": username}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiURL, "/")+"/token", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %s %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &storedToken{
		Username:    username,
		AccessToken: result.AccessToken,
		IDToken:     result.IDToken,
		Expiry:      time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}, nil
}

func loadSavedToken(path string) (*storedToken, error) {
	var token storedToken
	if err := readJSON(path, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func saveToken(path string, token *storedToken) error {
	return writeJSON(path, token)
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the local OIDC test API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := api.NewServer()
			addr := ":8080"
			fmt.Fprintf(cmd.OutOrStdout(), "starting local API server at %s\n", addr)
			return srv.ListenAndServe(addr)
		},
	}
	return cmd
}

func loginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login --user <name>",
		Short: "Authenticate against local API and save an ID token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			username, err := cmd.Flags().GetString("user")
			if err != nil {
				return err
			}
			if username == "" {
				return errors.New("--user is required")
			}
			ctx := cmd.Context()
			token, err := requestToken(ctx, apiURL, username)
			if err != nil {
				return err
			}
			dd, err := resolveDataDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dd, 0o700); err != nil {
				return err
			}
			path := filepath.Join(dd, "token.json")
			if err := saveToken(path, token); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "saved token for user %s to %s\n", username, path)
			return nil
		},
	}
	cmd.Flags().String("user", "", "username to authenticate")
	return cmd
}

func sshCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh <ip>",
		Short: "Obtain ID token, sign SSH certificate, and connect to node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			username, err := cmd.Flags().GetString("user")
			if err != nil {
				return err
			}
			if username == "" {
				return errors.New("--user is required")
			}
			certOnly, err := cmd.Flags().GetBool("cert-only")
			if err != nil {
				return err
			}

			dd, err := resolveDataDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(dd, 0o700); err != nil {
				return err
			}

			tokenPath := filepath.Join(dd, "token.json")
			token, err := loadSavedToken(tokenPath)
			if err != nil || time.Now().After(token.Expiry) || token.Username != username {
				fmt.Fprintf(cmd.OutOrStdout(), "token missing or expired, requesting a new one\n")
				token, err = requestToken(cmd.Context(), apiURL, username)
				if err != nil {
					return err
				}
				if err := saveToken(tokenPath, token); err != nil {
					return err
				}
			}

			keyBase := filepath.Join(dd, username)
			privKey := keyBase
			pubKey := keyBase + ".pub"
			certPath := keyBase + "-cert.pub"
			caKey := filepath.Join(dd, "ca")

			if err := ss.EnsureCA(caKey); err != nil {
				return err
			}
			if err := ss.EnsureUserKeyPair(username, privKey); err != nil {
				return err
			}
			if err := ss.CreateCertificate(username, token.IDToken, pubKey, certPath, caKey); err != nil {
				return err
			}

			if certOnly {
				fmt.Fprintf(cmd.OutOrStdout(), "certificate created at %s\n", certPath)
				return nil
			}

			shellArgs := []string{
				"ssh",
				"-i", privKey,
				"-o", "CertificateFile=" + certPath,
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				username + "@" + ip,
			}
			fmt.Fprintf(cmd.OutOrStdout(), "running: %s\n", strings.Join(shellArgs, " "))
			sshCmd := exec.CommandContext(cmd.Context(), shellArgs[0], shellArgs[1:]...)
			sshCmd.Stdin = os.Stdin
			sshCmd.Stdout = os.Stdout
			sshCmd.Stderr = os.Stderr
			return sshCmd.Run()
		},
	}
	cmd.Flags().String("user", "", "username to use for SSH and token issuance")
	cmd.Flags().Bool("cert-only", false, "only generate certificate, do not connect")
	return cmd
}

func verifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <cert.pub>",
		Short: "Verify a generated SSH certificate and its embedded ID token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath := args[0]
			caPub := filepath.Join(func() string {
				if d, err := resolveDataDir(); err == nil {
					return d
				}
				return ".qwe"
			}(), "ca.pub")
			result, err := ss.VerifyCertificate(certPath, caPub, apiURL)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "verified certificate for %s\n", result.Username)
			fmt.Fprintf(cmd.OutOrStdout(), "groups: %s\n", strings.Join(result.Groups, ", "))
			fmt.Fprintf(cmd.OutOrStdout(), "authorized sudo: %v\n", result.Sudo)
			return nil
		},
	}
	return cmd
}

func authKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth-keys <username> <key> <type>",
		Short: "AuthorizedKeysCommand for SSH: verify certificate and output key if authorized",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			username := args[0]
			keyStr := args[1]
			keyType := args[2]

			fmt.Fprintf(os.Stderr, "auth-keys: username=%s, keyType=%s\n", username, keyType)

			if !strings.Contains(keyType, "cert") {
				// Not a certificate, deny
				fmt.Fprintf(os.Stderr, "not a cert\n")
				return nil
			}

			// Create a temp file with the cert
			tempFile, err := os.CreateTemp("", "cert-*.pub")
			if err != nil {
				return err
			}
			defer os.Remove(tempFile.Name())
			defer tempFile.Close()

			fullKey := keyType + " " + keyStr
			if _, err := tempFile.WriteString(fullKey); err != nil {
				return err
			}
			tempFile.Close()

			caPub := filepath.Join(func() string {
				if d, err := resolveDataDir(); err == nil {
					return d
				}
				return ".qwe"
			}(), "ca.pub")

			fmt.Fprintf(os.Stderr, "verifying cert at %s with ca %s\n", tempFile.Name(), caPub)

			result, err := ss.VerifyCertificate(tempFile.Name(), caPub, apiURL)
			if err != nil {
				// Verification failed, deny
				fmt.Fprintf(os.Stderr, "verification failed: %v\n", err)
				return nil
			}

			if result.Username != username {
				// Username mismatch, deny
				fmt.Fprintf(os.Stderr, "username mismatch: %s != %s\n", result.Username, username)
				return nil
			}

			// Authorized, output the key
			fmt.Printf("%s\n", fullKey)
			return nil
		},
	}
	return cmd
}
