package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
)

var (
	outputFormat string // "table", "json", "raw"
	outputField  string // for -field=key
)

// printResult outputs data in the chosen format.
func printResult(data map[string]any) {
	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(data) //nolint:errcheck
	case "raw":
		if outputField != "" {
			if v, ok := data[outputField]; ok {
				fmt.Println(v)
			}
		} else {
			for k, v := range data {
				fmt.Printf("%s=%v\n", k, v)
			}
		}
	default: // table
		printTable(data)
	}
}

func printTable(data map[string]any) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	keys := sortedKeys(data)
	for _, k := range keys {
		v := data[k]
		switch val := v.(type) {
		case map[string]any:
			fmt.Fprintf(w, "%s\t\n", strings.ToUpper(k))
			for _, kk := range sortedKeys(val) {
				fmt.Fprintf(w, "  %s\t%v\n", kk, val[kk])
			}
		case []any:
			fmt.Fprintf(w, "%s\t%s\n", k, joinAny(val))
		default:
			fmt.Fprintf(w, "%s\t%v\n", k, v)
		}
	}
	w.Flush()
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func joinAny(vals []any) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%v", v)
	}
	return strings.Join(parts, ", ")
}

func printError(msg string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
}

func printSuccess(msg string) {
	fmt.Println(msg)
}
