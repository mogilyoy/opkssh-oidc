package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mastervolkov/opkssh-oidc/internal/oidc"
)

type jwksKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type tokenRequest struct {
	Username string `json:"username"`
	Nonce    string `json:"nonce"`
}

func (s *Server) ListenAndServe(addr string) error {
	h := s.routes()
	token := http.Server{Addr: addr, Handler: h}
	return token.ListenAndServe()
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/users", s.handleUsers)
	mux.HandleFunc("/groups", s.handleGroups)
	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "qwe local OIDC test API\n")
}

func (s *Server) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.issuer + "/authorize",
		"token_endpoint":         s.issuer + "/token",
		"jwks_uri":               s.issuer + "/jwks",
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, jwksResponse{Keys: []jwksKey{publicKeyToJWK(s.pubKey, s.jwkID)}})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Username = r.FormValue("username")
		req.Nonce = r.FormValue("nonce")
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	user, ok := s.users[req.Username]
	if !ok {
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}
	idToken, err := oidc.NewIDToken(s.issuer, user.Username, user.Email, user.Groups, req.Nonce, s.privKey, s.jwkID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, tokenResponse{
		AccessToken: fmt.Sprintf("token-%d", time.Now().UnixNano()),
		IDToken:     idToken,
		ExpiresIn:   900,
		TokenType:   "Bearer",
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	uid := r.URL.Query().Get("uid")
	if username != "" {
		user, ok := s.users[username]
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		writeJSON(w, user)
		return
	}
	if uid != "" {
		intUID, err := strconv.Atoi(uid)
		if err != nil {
			http.Error(w, "invalid uid", http.StatusBadRequest)
			return
		}
		for _, user := range s.users {
			if user.UID == intUID {
				writeJSON(w, user)
				return
			}
		}
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	writeJSON(w, list)
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	name := r.URL.Query().Get("name")
	gidStr := r.URL.Query().Get("gid")
	if username != "" {
		user, ok := s.users[username]
		if !ok {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		groups := make([]Group, 0, len(user.Groups))
		for _, n := range user.Groups {
			if g, ok := s.groups[n]; ok {
				groups = append(groups, g)
			}
		}
		writeJSON(w, groups)
		return
	}
	if name != "" {
		group, ok := s.groups[name]
		if !ok {
			http.Error(w, "group not found", http.StatusNotFound)
			return
		}
		writeJSON(w, group)
		return
	}
	if gidStr != "" {
		gid, err := strconv.Atoi(gidStr)
		if err != nil {
			http.Error(w, "invalid gid", http.StatusBadRequest)
			return
		}
		for _, g := range s.groups {
			if g.GID == gid {
				writeJSON(w, g)
				return
			}
		}
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	list := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		list = append(list, g)
	}
	writeJSON(w, list)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func publicKeyToJWK(pub ed25519.PublicKey, kid string) jwksKey {
	return jwksKey{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Alg: "EdDSA",
		Use: "sig",
		Kid: kid,
	}
}
