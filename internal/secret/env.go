package secret

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/org/secretvault/pkg/models"
)

const EnvFieldVars = "env_vars"

// EnvEngine wraps KVEngine with env-bundle helpers.
type EnvEngine struct {
	kv *KVEngine
}

// NewEnvEngine creates an EnvEngine.
func NewEnvEngine(kv *KVEngine) *EnvEngine {
	return &EnvEngine{kv: kv}
}

// Put stores an env bundle.
func (e *EnvEngine) Put(ctx context.Context, token *models.Token, path string, vars map[string]string) error {
	data := map[string]any{
		EnvFieldVars: vars,
	}
	_, err := e.kv.Put(ctx, token, path, "env", data)
	return err
}

// Get retrieves an env bundle.
func (e *EnvEngine) Get(ctx context.Context, token *models.Token, path string, version int) (map[string]string, error) {
	data, _, err := e.kv.Get(ctx, token, path, version)
	if err != nil {
		return nil, err
	}
	rawVars, ok := data[EnvFieldVars]
	if !ok {
		return map[string]string{}, nil
	}
	// json.Unmarshal gives map[string]interface{}
	switch v := rawVars.(type) {
	case map[string]any:
		result := make(map[string]string, len(v))
		for k, val := range v {
			result[k] = fmt.Sprintf("%v", val)
		}
		return result, nil
	case map[string]string:
		return v, nil
	default:
		return map[string]string{}, nil
	}
}

// ExportDotEnv renders env vars as a .env file format.
func ExportDotEnv(vars map[string]string) string {
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		v := vars[k]
		// Quote values that contain spaces or special chars
		if needsQuoting(v) {
			fmt.Fprintf(&buf, "%s=%q\n", k, v)
		} else {
			fmt.Fprintf(&buf, "%s=%s\n", k, v)
		}
	}
	return buf.String()
}

func needsQuoting(s string) bool {
	for _, c := range s {
		if c == ' ' || c == '\t' || c == '\n' || c == '"' || c == '\'' || c == '\\' || c == '#' {
			return true
		}
	}
	return false
}
