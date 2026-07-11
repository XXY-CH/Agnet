// agnet-key manages explicitly requested encrypted managed-key lifecycle operations.
package main

import (
	"agnet/internal/managedkey"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

var errOperationFailed = errors.New("operation failed")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = io.WriteString(os.Stderr, "agnet-key: operation failed\n")
		os.Exit(1)
	}
}

func run(args []string, stdout, _ io.Writer) error {
	if len(args) == 0 {
		return errOperationFailed
	}
	command := args[0]
	values, err := parseCommandFlags(command, args[1:])
	if err != nil {
		return errOperationFailed
	}
	store, err := managedkey.OpenStore(values["store"], nil)
	if err != nil {
		return errOperationFailed
	}
	var result managedkey.LifecycleResult
	switch command {
	case "migrate":
		iterations, iterationErr := parseIterations(values)
		if iterationErr != nil {
			return errOperationFailed
		}
		result, err = managedkey.Migrate(managedkey.MigrateOptions{
			Store:          store,
			SourceKeyPath:  values["key-file"],
			SourceKeyType:  values["key-type"],
			IdentityKind:   values["identity-kind"],
			DescriptorPath: values["descriptor"],
			PassphrasePath: values["passphrase-file"],
			Iterations:     iterations,
		})
	case "rewrap":
		iterations, iterationErr := parseIterations(values)
		if iterationErr != nil {
			return errOperationFailed
		}
		result, err = managedkey.Rewrap(managedkey.RewrapOptions{
			Store:             store,
			IdentityKind:      values["identity-kind"],
			DescriptorPath:    values["descriptor"],
			PassphrasePath:    values["current-passphrase-file"],
			NewPassphrasePath: values["new-passphrase-file"],
			Iterations:        iterations,
		})
	case "rotate":
		iterations, iterationErr := parseIterations(values)
		if iterationErr != nil {
			return errOperationFailed
		}
		zoneStore, zoneErr := managedkey.OpenStore(values["zone-store"], nil)
		if zoneErr != nil {
			return errOperationFailed
		}
		result, err = managedkey.RotateAgent(managedkey.RotateAgentOptions{
			Store:              store,
			ZoneStore:          zoneStore,
			PassphrasePath:     values["passphrase-file"],
			ZonePassphrasePath: values["zone-passphrase-file"],
			Iterations:         iterations,
		})
	case "recover":
		result, err = managedkey.Recover(managedkey.RecoverOptions{Store: store, PassphrasePath: values["passphrase-file"]})
	default:
		return errOperationFailed
	}
	if err != nil {
		return errOperationFailed
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return errOperationFailed
	}
	return nil
}

func parseCommandFlags(command string, args []string) (map[string]string, error) {
	allowed, required := commandFlagSet(command)
	if allowed == nil {
		return nil, errOperationFailed
	}
	values := make(map[string]string, len(required))
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) || !strings.HasPrefix(args[index], "--") || strings.Contains(args[index], "=") || strings.HasPrefix(args[index+1], "--") {
			return nil, errOperationFailed
		}
		name := strings.TrimPrefix(args[index], "--")
		if !allowed[name] || args[index+1] == "" {
			return nil, errOperationFailed
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errOperationFailed
		}
		values[name] = args[index+1]
	}
	for _, name := range required {
		if values[name] == "" {
			return nil, errOperationFailed
		}
	}
	return values, nil
}

func commandFlagSet(command string) (map[string]bool, []string) {
	switch command {
	case "migrate":
		required := []string{"store", "key-file", "key-type", "identity-kind", "descriptor", "passphrase-file"}
		return map[string]bool{"store": true, "key-file": true, "key-type": true, "identity-kind": true, "descriptor": true, "passphrase-file": true, "iterations": true}, required
	case "rewrap":
		required := []string{"store", "identity-kind", "descriptor", "current-passphrase-file", "new-passphrase-file"}
		return map[string]bool{"store": true, "identity-kind": true, "descriptor": true, "current-passphrase-file": true, "new-passphrase-file": true, "iterations": true}, required
	case "recover":
		required := []string{"store", "passphrase-file"}
		return map[string]bool{"store": true, "passphrase-file": true}, required
	case "rotate":
		required := []string{"store", "passphrase-file", "zone-store", "zone-passphrase-file"}
		return map[string]bool{"store": true, "passphrase-file": true, "zone-store": true, "zone-passphrase-file": true, "iterations": true}, required
	default:
		return nil, nil
	}
}

func parseIterations(values map[string]string) (int, error) {
	encoded, ok := values["iterations"]
	if !ok {
		return 0, nil
	}
	iterations, err := strconv.Atoi(encoded)
	if err != nil || iterations < 100000 || iterations > 2000000 {
		return 0, errOperationFailed
	}
	return iterations, nil
}
