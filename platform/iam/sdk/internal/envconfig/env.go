// Package envconfig implements the SDK's IQ_* environment contract and the
// temporary compatibility bridge for workloads using MOTIVEIQ_* variables.
package envconfig

import "strings"

// Get prefers the canonical name, then its legacy alias. The role and token
// file are selected together: a partial IQ_* identity must never pick up the
// missing half from a different, ambient legacy identity.
func Get(getenv func(string) string, name string) string {
	if name == "IQ_ROLE_URN" || name == "IQ_WEB_IDENTITY_TOKEN_FILE" {
		if getenv("IQ_ROLE_URN") != "" || getenv("IQ_WEB_IDENTITY_TOKEN_FILE") != "" {
			return getenv(name)
		}
	}
	if value := getenv(name); value != "" {
		return value
	}
	return getenv("MOTIVEIQ_" + strings.TrimPrefix(name, "IQ_"))
}
