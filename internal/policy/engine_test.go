package policy

import (
	"context"
	"testing"

	"github.com/org/secretvault/pkg/models"
)

// mockPolicyStore is a minimal in-memory PolicyGetter for testing.
type mockPolicyStore struct {
	policies map[string]*models.Policy
}

func newMockStore(pols ...*models.Policy) *mockPolicyStore {
	m := &mockPolicyStore{policies: map[string]*models.Policy{}}
	for _, p := range pols {
		m.policies[p.Name] = p
	}
	return m
}

func (m *mockPolicyStore) GetPolicy(_ context.Context, name string) (*models.Policy, error) {
	if p, ok := m.policies[name]; ok {
		return p, nil
	}
	return nil, nil
}

func TestPolicyExactMatch(t *testing.T) {
	pol := &models.Policy{
		Name: "test",
		Rules: map[string]models.PathRule{
			"secret/data/myapp": {Capabilities: []string{"read"}},
		},
	}
	eng := NewEngine(newMockStore(pol))
	ctx := context.Background()

	if !eng.IsAllowed(ctx, []string{"test"}, "read", "secret/data/myapp") {
		t.Error("expected read to be allowed on exact match")
	}
	if eng.IsAllowed(ctx, []string{"test"}, "write", "secret/data/myapp") {
		t.Error("expected write to be denied")
	}
}

func TestPolicySingleWildcard(t *testing.T) {
	pol := &models.Policy{
		Name: "test",
		Rules: map[string]models.PathRule{
			"secret/data/*": {Capabilities: []string{"read", "write"}},
		},
	}
	eng := NewEngine(newMockStore(pol))
	ctx := context.Background()

	cases := []struct {
		path    string
		allowed bool
	}{
		{"secret/data/myapp", true},
		{"secret/data/db", true},
		{"secret/data/myapp/db", false}, // * doesn't cross segments
		{"secret/metadata/myapp", false},
	}
	for _, tc := range cases {
		got := eng.IsAllowed(ctx, []string{"test"}, "read", tc.path)
		if got != tc.allowed {
			t.Errorf("path=%q: expected allowed=%v got %v", tc.path, tc.allowed, got)
		}
	}
}

func TestPolicyGlobStar(t *testing.T) {
	pol := &models.Policy{
		Name: "test",
		Rules: map[string]models.PathRule{
			"secret/**": {Capabilities: []string{"read"}},
		},
	}
	eng := NewEngine(newMockStore(pol))
	ctx := context.Background()

	for _, p := range []string{"secret/data/myapp", "secret/data/a/b/c", "secret/metadata/db"} {
		if !eng.IsAllowed(ctx, []string{"test"}, "read", p) {
			t.Errorf("expected read allowed on %q", p)
		}
	}
	if eng.IsAllowed(ctx, []string{"test"}, "read", "auth/token/create") {
		t.Error("auth path should not be allowed")
	}
}

func TestRootPolicy(t *testing.T) {
	root := &models.Policy{
		Name: "root",
		Rules: map[string]models.PathRule{
			"*": {Capabilities: []string{"sudo"}},
		},
	}
	eng := NewEngine(newMockStore(root))
	ctx := context.Background()

	for _, cap := range []string{"read", "write", "delete", "list", "sudo"} {
		if !eng.IsAllowed(ctx, []string{"root"}, cap, "anything/here") {
			t.Errorf("root policy should allow %q on any path", cap)
		}
	}
}

func TestMultiplePolicies(t *testing.T) {
	readPol := &models.Policy{
		Name:  "reader",
		Rules: map[string]models.PathRule{"secret/data/*": {Capabilities: []string{"read"}}},
	}
	writePol := &models.Policy{
		Name:  "writer",
		Rules: map[string]models.PathRule{"secret/data/myapp": {Capabilities: []string{"write"}}},
	}
	eng := NewEngine(newMockStore(readPol, writePol))
	ctx := context.Background()

	if !eng.IsAllowed(ctx, []string{"reader", "writer"}, "write", "secret/data/myapp") {
		t.Error("write should be allowed via writer policy")
	}
	if !eng.IsAllowed(ctx, []string{"reader", "writer"}, "read", "secret/data/other") {
		t.Error("read should be allowed via reader policy")
	}
	if eng.IsAllowed(ctx, []string{"reader"}, "write", "secret/data/myapp") {
		t.Error("write should not be allowed with only reader policy")
	}
}
