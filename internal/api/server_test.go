package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/org/secretvault/internal/auth"
	"github.com/org/secretvault/internal/core"
	"github.com/org/secretvault/internal/policy"
	"github.com/org/secretvault/internal/secret"
	"github.com/org/secretvault/internal/storage"
	"github.com/org/secretvault/pkg/models"
)

// --- In-memory storage backend for tests ---

type memStore struct {
	initData   *models.InitData
	tokens     map[string]*models.Token // keyed by token_hash
	tokensByID map[string]*models.Token
	policies   map[string]*models.Policy
	secrets    map[string][]*models.SecretVersion // path → versions
	secretMeta map[string]*models.SecretMetadata
	audit      []*models.AuditEntry
	roles      map[string]*models.AppRole
	appSecrets map[string]*models.AppRoleSecret
}

func newMemStore() *memStore {
	s := &memStore{
		tokens:     map[string]*models.Token{},
		tokensByID: map[string]*models.Token{},
		policies: map[string]*models.Policy{
			"root": {
				Name: "root",
				Rules: map[string]models.PathRule{
					"*": {Capabilities: []string{"sudo", "read", "write", "list", "delete"}},
				},
			},
			"default": {
				Name: "default",
				Rules: map[string]models.PathRule{
					"auth/token/lookup-self": {Capabilities: []string{"read"}},
				},
			},
		},
		secrets:    map[string][]*models.SecretVersion{},
		secretMeta: map[string]*models.SecretMetadata{},
		roles:      map[string]*models.AppRole{},
		appSecrets: map[string]*models.AppRoleSecret{},
	}
	return s
}

func (m *memStore) InitVault(ctx context.Context, d *models.InitData) error {
	m.initData = d
	return nil
}
func (m *memStore) GetInitData(ctx context.Context) (*models.InitData, error) {
	if m.initData == nil {
		return nil, storage.ErrNotFound
	}
	return m.initData, nil
}
func (m *memStore) IsInitialized(ctx context.Context) (bool, error) {
	return m.initData != nil, nil
}

func (m *memStore) WriteSecretVersion(ctx context.Context, path, secretType string, v *models.SecretVersion) error {
	versions := m.secrets[path]
	v.Version = len(versions) + 1
	v.SecretID = int64(len(m.secrets) + 1)
	m.secrets[path] = append(versions, v)

	meta := m.secretMeta[path]
	if meta == nil {
		meta = &models.SecretMetadata{Path: path, Type: secretType, CreatedAt: v.CreatedAt}
	}
	meta.CurrentVersion = v.Version
	meta.UpdatedAt = v.CreatedAt
	meta.Versions = append(meta.Versions, models.VersionInfo{
		Version:   v.Version,
		CreatedAt: v.CreatedAt,
	})
	m.secretMeta[path] = meta
	return nil
}

func (m *memStore) ReadSecretVersion(ctx context.Context, path string, version int) (*models.SecretVersion, error) {
	versions := m.secrets[path]
	for _, v := range versions {
		if v.Version == version {
			return v, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (m *memStore) ReadLatestSecretVersion(ctx context.Context, path string) (*models.SecretVersion, error) {
	versions := m.secrets[path]
	if len(versions) == 0 {
		return nil, storage.ErrNotFound
	}
	return versions[len(versions)-1], nil
}

func (m *memStore) ListSecrets(ctx context.Context, prefix string) ([]string, error) {
	var result []string
	for p := range m.secrets {
		if len(p) >= len(prefix) && p[:len(prefix)] == prefix {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *memStore) DeleteSecretVersions(ctx context.Context, path string, versions []int) error {
	now := time.Now()
	for _, v := range m.secrets[path] {
		for _, ver := range versions {
			if v.Version == ver {
				v.DeletedAt = &now
			}
		}
	}
	return nil
}

func (m *memStore) UndeleteSecretVersions(ctx context.Context, path string, versions []int) error {
	for _, v := range m.secrets[path] {
		for _, ver := range versions {
			if v.Version == ver {
				v.DeletedAt = nil
			}
		}
	}
	return nil
}

func (m *memStore) DestroySecretVersions(ctx context.Context, path string, versions []int) error {
	for _, v := range m.secrets[path] {
		for _, ver := range versions {
			if v.Version == ver {
				v.Destroyed = true
				v.EncryptedDEK = nil
				v.Ciphertext = nil
			}
		}
	}
	return nil
}

func (m *memStore) GetSecretMetadata(ctx context.Context, path string) (*models.SecretMetadata, error) {
	if meta, ok := m.secretMeta[path]; ok {
		return meta, nil
	}
	return nil, storage.ErrNotFound
}

func (m *memStore) WriteToken(ctx context.Context, token *models.Token) error {
	m.tokens[token.ID] = token
	m.tokensByID[token.ID] = token
	return nil
}

func (m *memStore) WriteTokenWithHash(ctx context.Context, token *models.Token, hash string) error {
	m.tokens[hash] = token
	m.tokensByID[token.ID] = token
	return nil
}

func (m *memStore) GetToken(ctx context.Context, tokenHash string) (*models.Token, error) {
	if t, ok := m.tokens[tokenHash]; ok {
		return t, nil
	}
	return nil, storage.ErrNotFound
}

func (m *memStore) RevokeToken(ctx context.Context, tokenID string) error {
	if t, ok := m.tokensByID[tokenID]; ok {
		now := time.Now()
		t.RevokedAt = &now
	}
	return nil
}

func (m *memStore) RevokeTokenChildren(ctx context.Context, parentID string) error { return nil }

func (m *memStore) RenewToken(ctx context.Context, tokenID string, newExpiresAt interface{}) error {
	return nil
}

func (m *memStore) WriteAppRole(ctx context.Context, role *models.AppRole) error {
	m.roles[role.Name] = role
	return nil
}
func (m *memStore) GetAppRole(ctx context.Context, name string) (*models.AppRole, error) {
	if r, ok := m.roles[name]; ok {
		return r, nil
	}
	return nil, storage.ErrNotFound
}
func (m *memStore) GetAppRoleByID(ctx context.Context, roleID string) (*models.AppRole, error) {
	for _, r := range m.roles {
		if r.ID == roleID {
			return r, nil
		}
	}
	return nil, storage.ErrNotFound
}
func (m *memStore) WriteAppRoleSecret(ctx context.Context, s *models.AppRoleSecret) error {
	m.appSecrets[s.SecretIDHash] = s
	return nil
}
func (m *memStore) GetAppRoleSecret(ctx context.Context, hash string) (*models.AppRoleSecret, error) {
	if s, ok := m.appSecrets[hash]; ok {
		return s, nil
	}
	return nil, storage.ErrNotFound
}
func (m *memStore) ConsumeAppRoleSecret(ctx context.Context, hash string) error { return nil }

func (m *memStore) WritePolicy(ctx context.Context, p *models.Policy) error {
	m.policies[p.Name] = p
	return nil
}
func (m *memStore) GetPolicy(ctx context.Context, name string) (*models.Policy, error) {
	if p, ok := m.policies[name]; ok {
		return p, nil
	}
	return nil, storage.ErrNotFound
}
func (m *memStore) DeletePolicy(ctx context.Context, name string) error {
	delete(m.policies, name)
	return nil
}
func (m *memStore) ListPolicies(ctx context.Context) ([]string, error) {
	var names []string
	for n := range m.policies {
		names = append(names, n)
	}
	return names, nil
}

func (m *memStore) WriteAuditEntry(ctx context.Context, e *models.AuditEntry) error {
	m.audit = append(m.audit, e)
	return nil
}
func (m *memStore) QueryAuditLog(ctx context.Context, filter storage.AuditFilter) ([]*models.AuditEntry, error) {
	return m.audit, nil
}

func (m *memStore) CountSecrets(ctx context.Context) (int64, error)       { return int64(len(m.secrets)), nil }
func (m *memStore) CountActiveTokens(ctx context.Context) (int64, error)  { return int64(len(m.tokens)), nil }
func (m *memStore) Close()                                                 {}

// --- test helpers ---

func newTestServer() (*Server, *memStore) {
	store := newMemStore()
	sealMgr := core.NewSealManager(3)
	tokenSvc := auth.NewTokenService(store)
	approleAuth := auth.NewAppRoleService(store, tokenSvc)
	policyEng := policy.NewEngine(store)
	kvEng := secret.NewKVEngine(store, sealMgr, policyEng)
	// Use audit.NewLogger but it needs storage.StorageBackend
	// Create a minimal no-op logger via the real one
	srv := &Server{
		store:   store,
		seal:    sealMgr,
		tokens:  tokenSvc,
		approle: approleAuth,
		policy:  policyEng,
		kv:      kvEng,
		auditor: newTestAuditLogger(store),
		cfg:     Config{UnsealThreshold: 3},
	}
	return srv, store
}

func newTestAuditLogger(store storage.StorageBackend) AuditLogger {
	return &noopAudit{store: store}
}

type noopAudit struct{ store storage.StorageBackend }

func (n *noopAudit) LogRequest(ctx context.Context, e *models.AuditEntry) {
	_ = n.store.WriteAuditEntry(ctx, e)
}
func (n *noopAudit) Query(ctx context.Context, f storage.AuditFilter) ([]*models.AuditEntry, error) {
	return n.store.QueryAuditLog(ctx, f)
}

func createRootToken(t *testing.T, srv *Server, store storage.StorageBackend) string {
	t.Helper()
	ctx := context.Background()
	_, plaintext, err := srv.tokens.CreateToken(ctx, "root", []string{"root"}, 0, false, nil)
	if err != nil {
		t.Fatalf("creating root token: %v", err)
	}
	return plaintext
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, token string) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func getJSON(t *testing.T, handler http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v (body: %s)", err, w.Body.String())
	}
	return result
}

// --- tests ---

func TestHealthEndpoint(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()

	w := getJSON(t, handler, "/v1/sys/health", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 (sealed), got %d", w.Code)
	}
	body := decodeBody(t, w)
	if sealed, _ := body["sealed"].(bool); !sealed {
		t.Error("expected sealed=true")
	}
}

func TestInitAndSealStatus(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()

	// Init
	w := postJSON(t, handler, "/v1/sys/init", map[string]any{
		"secret_shares": 3, "secret_threshold": 2,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("init failed: %d %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if _, ok := body["keys"]; !ok {
		t.Error("expected keys in init response")
	}
	// After init, vault is auto-unsealed
	if sealed, _ := body["initialized"].(bool); !sealed {
		t.Error("expected initialized=true")
	}

	// Health should now return 200
	w2 := getJSON(t, handler, "/v1/sys/health", "")
	if w2.Code != http.StatusOK {
		t.Errorf("expected 200 after unseal, got %d", w2.Code)
	}
}

func TestKVPutGet(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()

	// Init to unseal
	postJSON(t, handler, "/v1/sys/init", map[string]any{"secret_shares": 3, "secret_threshold": 2}, "")

	// Create root token
	rootToken := createRootToken(t, srv, srv.store)

	// Put secret
	w := postJSON(t, handler, "/v1/secret/data/myapp/db", map[string]any{
		"data": map[string]any{"password": "hunter2", "user": "admin"},
	}, rootToken)
	if w.Code != http.StatusOK {
		t.Fatalf("put failed: %d %s", w.Code, w.Body.String())
	}

	// Get secret
	w2 := getJSON(t, handler, "/v1/secret/data/myapp/db", rootToken)
	if w2.Code != http.StatusOK {
		t.Fatalf("get failed: %d %s", w2.Code, w2.Body.String())
	}
	body := decodeBody(t, w2)
	data := body["data"].(map[string]any)["data"].(map[string]any)
	if data["password"] != "hunter2" {
		t.Errorf("expected password=hunter2, got %v", data["password"])
	}
	if data["user"] != "admin" {
		t.Errorf("expected user=admin, got %v", data["user"])
	}
}

func TestTokenCreateAndLookup(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()
	postJSON(t, handler, "/v1/sys/init", map[string]any{"secret_shares": 3, "secret_threshold": 2}, "")

	rootToken := createRootToken(t, srv, srv.store)

	// Create child token
	w := postJSON(t, handler, "/v1/auth/token/create", map[string]any{
		"policies": []string{"default"},
		"ttl":      "1h",
	}, rootToken)
	if w.Code != http.StatusOK {
		t.Fatalf("token create failed: %d %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	authData := body["auth"].(map[string]any)
	childToken := authData["client_token"].(string)
	if childToken == "" {
		t.Error("expected client_token in response")
	}

	// Lookup self
	w2 := getJSON(t, handler, "/v1/auth/token/lookup-self", childToken)
	if w2.Code != http.StatusOK {
		t.Fatalf("lookup-self failed: %d %s", w2.Code, w2.Body.String())
	}
}

func TestPolicyListAndRead(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()
	postJSON(t, handler, "/v1/sys/init", map[string]any{"secret_shares": 3, "secret_threshold": 2}, "")
	rootToken := createRootToken(t, srv, srv.store)

	w := getJSON(t, handler, "/v1/sys/policy", rootToken)
	if w.Code != http.StatusOK {
		t.Fatalf("policy list failed: %d %s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["policies"] == nil {
		t.Error("expected policies list")
	}
}

func TestSealAndReseal(t *testing.T) {
	srv, _ := newTestServer()
	handler := srv.BuildRouter()
	postJSON(t, handler, "/v1/sys/init", map[string]any{"secret_shares": 3, "secret_threshold": 2}, "")
	rootToken := createRootToken(t, srv, srv.store)

	// Seal
	req := httptest.NewRequest("PUT", "/v1/sys/seal", nil)
	req.Header.Set("X-Vault-Token", rootToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("seal failed: %d", w.Code)
	}
	if !srv.seal.IsSealed() {
		t.Error("vault should be sealed after PUT /v1/sys/seal")
	}
}
