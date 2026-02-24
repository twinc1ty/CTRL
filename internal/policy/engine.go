package policy

import (
	"context"
	"path"
	"strings"

	"github.com/org/secretvault/pkg/models"
)

// PolicyGetter is the minimal interface the Engine needs from storage.
type PolicyGetter interface {
	GetPolicy(ctx context.Context, name string) (*models.Policy, error)
}

// Engine evaluates access policies for a given token and operation.
type Engine struct {
	store PolicyGetter
}

// NewEngine creates a new policy Engine backed by the given storage.
func NewEngine(store PolicyGetter) *Engine {
	return &Engine{store: store}
}

// IsAllowed returns true if any of the token's policies grant the capability on the path.
func (e *Engine) IsAllowed(ctx context.Context, policies []string, capability, reqPath string) bool {
	for _, policyName := range policies {
		pol, err := e.store.GetPolicy(ctx, policyName)
		if err != nil {
			continue
		}
		if policyAllows(pol, capability, reqPath) {
			return true
		}
	}
	return false
}

// policyAllows returns true if the given policy grants the capability on reqPath.
func policyAllows(pol *models.Policy, capability, reqPath string) bool {
	for pattern, rule := range pol.Rules {
		if matchPath(pattern, reqPath) {
			if rule.HasCapability(capability) {
				return true
			}
		}
	}
	return false
}

// matchPath matches reqPath against a glob pattern.
// Supports Vault-style globs:
//   - "secret/data/*"  — matches one additional path segment
//   - "secret/**"      — matches any number of segments (including zero)
//   - "*"              — matches any path entirely (used by root policy)
func matchPath(pattern, reqPath string) bool {
	// Normalize
	pattern = strings.TrimPrefix(pattern, "/")
	reqPath = strings.TrimPrefix(reqPath, "/")

	// Bare "*" matches everything (root policy wildcard)
	if pattern == "*" {
		return true
	}

	// Handle "**" suffix — everything after the prefix
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := parts[1]
		if !strings.HasPrefix(reqPath, prefix) {
			return false
		}
		rest := reqPath[len(prefix):]
		if suffix == "" || suffix == "/" {
			return true
		}
		return strings.HasSuffix(rest, strings.TrimPrefix(suffix, "/"))
	}

	matched, err := path.Match(pattern, reqPath)
	if err != nil {
		return false
	}
	return matched
}

// GetEffectiveCapabilities returns all capabilities granted on a path across all policies.
func (e *Engine) GetEffectiveCapabilities(ctx context.Context, policies []string, reqPath string) []string {
	capSet := map[string]bool{}
	for _, policyName := range policies {
		pol, err := e.store.GetPolicy(ctx, policyName)
		if err != nil {
			continue
		}
		for pattern, rule := range pol.Rules {
			if matchPath(pattern, reqPath) {
				for _, c := range rule.Capabilities {
					capSet[c] = true
				}
			}
		}
	}
	caps := make([]string, 0, len(capSet))
	for c := range capSet {
		caps = append(caps, c)
	}
	return caps
}
