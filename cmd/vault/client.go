package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client is an HTTP client for the SecretVault API.
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// newClient creates a Client from the current config.
func newClient() *Client {
	addr := cfg.Address
	if v := os.Getenv("VAULT_ADDR"); v != "" {
		addr = v
	}
	token := cfg.Token
	if v := os.Getenv("VAULT_TOKEN"); v != "" {
		token = v
	}
	caCert := cfg.TLSCACert
	if v := os.Getenv("VAULT_CACERT"); v != "" {
		caCert = v
	}

	tlsCfg := &tls.Config{}
	if caCert != "" {
		data, err := os.ReadFile(caCert)
		if err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(data)
			tlsCfg.RootCAs = pool
		}
	}

	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}

	return &Client{addr: addr, token: token, http: httpClient}
}

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.addr+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}

	return c.http.Do(req)
}

func (c *Client) get(path string) (map[string]any, error) {
	resp, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	return parseResponse(resp)
}

func (c *Client) post(path string, body any) (map[string]any, error) {
	resp, err := c.do("POST", path, body)
	if err != nil {
		return nil, err
	}
	return parseResponse(resp)
}

func (c *Client) put(path string, body any) (map[string]any, error) {
	resp, err := c.do("PUT", path, body)
	if err != nil {
		return nil, err
	}
	return parseResponse(resp)
}

func (c *Client) delete(path string, body any) error {
	resp, err := c.do("DELETE", path, body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) list(path string) (map[string]any, error) {
	sep := "?"
	if len(path) > 0 && path[len(path)-1] == '?' {
		sep = ""
	}
	resp, err := c.do("GET", path+sep+"list=true", nil)
	if err != nil {
		return nil, err
	}
	return parseResponse(resp)
}

func parseResponse(resp *http.Response) (map[string]any, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, data)
	}
	if resp.StatusCode >= 400 {
		if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
			return nil, fmt.Errorf("%v", errs[0])
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return result, nil
}
