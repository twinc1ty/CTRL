package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "vault",
	Short: "SecretVault CLI",
	Long:  "A CLI for managing secrets in SecretVault.",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadConfig()
		// Env var overrides are applied in newClient()
	},
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&outputFormat, "format", "table", "Output format: table, json, raw")
	rootCmd.PersistentFlags().StringVar(&outputField, "field", "", "Print only this field (use with -format=raw)")

	rootCmd.AddCommand(operatorCmd())
	rootCmd.AddCommand(kvCmd())
	rootCmd.AddCommand(policyCmd())
	rootCmd.AddCommand(authCmd())
	rootCmd.AddCommand(tokenCmd())
}

// --- operator ---

func operatorCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "operator", Short: "Vault operator commands"}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			shares, _ := cmd.Flags().GetInt("shares")
			threshold, _ := cmd.Flags().GetInt("threshold")
			client := newClient()
			result, err := client.post("/v1/sys/init", map[string]any{
				"secret_shares":    shares,
				"secret_threshold": threshold,
			})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}
	initCmd.Flags().Int("shares", 5, "Number of key shares")
	initCmd.Flags().Int("threshold", 3, "Number of shares required to unseal")

	unsealCmd := &cobra.Command{
		Use:   "unseal",
		Short: "Provide an unseal key shard",
		RunE: func(cmd *cobra.Command, args []string) error {
			var key string
			if len(args) > 0 {
				key = args[0]
			} else {
				fmt.Print("Unseal Key (base64): ")
				scanner := bufio.NewScanner(os.Stdin)
				scanner.Scan()
				key = strings.TrimSpace(scanner.Text())
			}
			client := newClient()
			result, err := client.post("/v1/sys/unseal", map[string]any{"key": key})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}

	sealCmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal the vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			result, err := client.put("/v1/sys/seal", nil)
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}

	cmd.AddCommand(initCmd, unsealCmd, sealCmd)
	return cmd
}

// --- kv ---

func kvCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "kv", Short: "Interact with the KV secret engine"}

	putCmd := &cobra.Command{
		Use:   "put <path> [key=value ...]",
		Short: "Write a secret",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data := map[string]any{}
			for _, kv := range args[1:] {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid key=value pair: %s", kv)
				}
				data[parts[0]] = parts[1]
			}
			client := newClient()
			result, err := client.post("/v1/secret/data/"+path, map[string]any{"data": data})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}

	getCmd := &cobra.Command{
		Use:   "get <path>",
		Short: "Read a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			version, _ := cmd.Flags().GetString("version")
			url := "/v1/secret/data/" + path
			if version != "" {
				url += "?version=" + version
			}
			client := newClient()
			result, err := client.get(url)
			if err != nil {
				printError(err.Error())
				return nil
			}
			// Extract the nested data
			if d, ok := result["data"].(map[string]any); ok {
				if inner, ok := d["data"].(map[string]any); ok {
					printResult(inner)
					return nil
				}
			}
			printResult(result)
			return nil
		},
	}
	getCmd.Flags().String("version", "", "Version to read (default: latest)")

	listCmd := &cobra.Command{
		Use:   "list <prefix>",
		Short: "List secrets",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]
			client := newClient()
			result, err := client.list("/v1/secret/metadata/" + prefix)
			if err != nil {
				printError(err.Error())
				return nil
			}
			if d, ok := result["data"].(map[string]any); ok {
				if keys, ok := d["keys"].([]any); ok {
					for _, k := range keys {
						fmt.Println(k)
					}
					return nil
				}
			}
			printResult(result)
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete a secret version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			client := newClient()
			if err := client.delete("/v1/secret/data/"+path, nil); err != nil {
				printError(err.Error())
				return nil
			}
			printSuccess("Success! Data deleted.")
			return nil
		},
	}

	metaCmd := &cobra.Command{Use: "metadata", Short: "Metadata subcommands"}
	metaGetCmd := &cobra.Command{
		Use:   "get <path>",
		Short: "Get secret metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			result, err := client.get("/v1/secret/metadata/" + args[0])
			if err != nil {
				printError(err.Error())
				return nil
			}
			if d, ok := result["data"].(map[string]any); ok {
				printResult(d)
				return nil
			}
			printResult(result)
			return nil
		},
	}
	metaCmd.AddCommand(metaGetCmd)

	rotateCmd := &cobra.Command{
		Use:   "rotate <path> [key=value ...]",
		Short: "Rotate a secret (write new version)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			data := map[string]any{}
			for _, kv := range args[1:] {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) == 2 {
					data[parts[0]] = parts[1]
				}
			}
			client := newClient()
			result, err := client.post("/v1/secret/data/"+path, map[string]any{"data": data})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}

	cmd.AddCommand(putCmd, getCmd, listCmd, deleteCmd, metaCmd, rotateCmd)
	return cmd
}

// --- policy ---

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Manage policies"}

	writeCmd := &cobra.Command{
		Use:   "write <name> <file>",
		Short: "Write a policy from a JSON file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			data, err := os.ReadFile(args[1])
			if err != nil {
				printError(err.Error())
				return nil
			}
			var body map[string]any
			if err := parseJSON(data, &body); err != nil {
				printError(err.Error())
				return nil
			}
			client := newClient()
			_, err = client.post("/v1/sys/policy/"+name, body)
			if err != nil {
				printError(err.Error())
				return nil
			}
			printSuccess("Success! Uploaded policy: " + name)
			return nil
		},
	}

	readCmd := &cobra.Command{
		Use:   "read <name>",
		Short: "Read a policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			result, err := client.get("/v1/sys/policy/" + args[0])
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}

	deleteCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			if err := client.delete("/v1/sys/policy/"+args[0], nil); err != nil {
				printError(err.Error())
				return nil
			}
			printSuccess("Success! Deleted policy: " + args[0])
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			result, err := client.get("/v1/sys/policy")
			if err != nil {
				printError(err.Error())
				return nil
			}
			if policies, ok := result["policies"].([]any); ok {
				for _, p := range policies {
					fmt.Println(p)
				}
				return nil
			}
			printResult(result)
			return nil
		},
	}

	cmd.AddCommand(writeCmd, readCmd, deleteCmd, listCmd)
	return cmd
}

// --- auth ---

func authCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Auth method commands"}
	approleCmd := &cobra.Command{Use: "approle", Short: "AppRole auth"}
	roleCmd := &cobra.Command{Use: "role", Short: "Role management"}

	createRoleCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an AppRole",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, _ := cmd.Flags().GetStringSlice("policies")
			sidTTL, _ := cmd.Flags().GetString("secret-id-ttl")
			tokTTL, _ := cmd.Flags().GetString("token-ttl")
			client := newClient()
			result, err := client.post("/v1/auth/approle/role", map[string]any{
				"name":            args[0],
				"token_policies":  policies,
				"secret_id_ttl":   sidTTL,
				"token_ttl":       tokTTL,
			})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printResult(result)
			return nil
		},
	}
	createRoleCmd.Flags().StringSlice("policies", []string{"default"}, "Policies for the role")
	createRoleCmd.Flags().String("secret-id-ttl", "", "TTL for secret IDs (e.g. 24h)")
	createRoleCmd.Flags().String("token-ttl", "1h", "TTL for issued tokens")

	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Login with AppRole",
		RunE: func(cmd *cobra.Command, args []string) error {
			roleID, _ := cmd.Flags().GetString("role-id")
			secretID, _ := cmd.Flags().GetString("secret-id")
			client := newClient()
			result, err := client.post("/v1/auth/approle/login", map[string]any{
				"role_id":   roleID,
				"secret_id": secretID,
			})
			if err != nil {
				printError(err.Error())
				return nil
			}
			if auth, ok := result["auth"].(map[string]any); ok {
				if tok, ok := auth["client_token"].(string); ok {
					cfg.Token = tok
					if err := saveConfig(); err == nil {
						fmt.Fprintln(os.Stderr, "Token saved to config.")
					}
				}
				printResult(auth)
				return nil
			}
			printResult(result)
			return nil
		},
	}
	loginCmd.Flags().String("role-id", "", "Role ID")
	loginCmd.Flags().String("secret-id", "", "Secret ID")

	roleCmd.AddCommand(createRoleCmd)
	approleCmd.AddCommand(roleCmd, loginCmd)
	cmd.AddCommand(approleCmd)
	return cmd
}

// --- token ---

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "Token management"}

	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a token",
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, _ := cmd.Flags().GetStringSlice("policy")
			ttl, _ := cmd.Flags().GetString("ttl")
			renewable, _ := cmd.Flags().GetBool("renewable")
			client := newClient()
			result, err := client.post("/v1/auth/token/create", map[string]any{
				"policies":  policies,
				"ttl":       ttl,
				"renewable": renewable,
			})
			if err != nil {
				printError(err.Error())
				return nil
			}
			if auth, ok := result["auth"].(map[string]any); ok {
				printResult(auth)
				return nil
			}
			printResult(result)
			return nil
		},
	}
	createCmd.Flags().StringSlice("policy", []string{"default"}, "Policies to attach")
	createCmd.Flags().String("ttl", "", "Token TTL (e.g. 24h)")
	createCmd.Flags().Bool("renewable", false, "Whether token is renewable")

	revokeCmd := &cobra.Command{
		Use:   "revoke <token>",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			_, err := client.post("/v1/auth/token/revoke", map[string]any{"token": args[0]})
			if err != nil {
				printError(err.Error())
				return nil
			}
			printSuccess("Success! Token revoked.")
			return nil
		},
	}

	lookupCmd := &cobra.Command{
		Use:   "lookup",
		Short: "Look up the current token",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := newClient()
			result, err := client.get("/v1/auth/token/lookup-self")
			if err != nil {
				printError(err.Error())
				return nil
			}
			if d, ok := result["data"].(map[string]any); ok {
				printResult(d)
				return nil
			}
			printResult(result)
			return nil
		},
	}

	cmd.AddCommand(createCmd, revokeCmd, lookupCmd)
	return cmd
}

// helpers

func parseJSON(data []byte, dst any) error {
	return jsonUnmarshal(data, dst)
}
