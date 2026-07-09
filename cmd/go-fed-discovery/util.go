package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func policyStringList(value any, message string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if typed, ok := value.([]string); ok {
		return typed, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, errors.New(message)
	}
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New(message)
		}
		out = append(out, text)
	}
	return out, nil
}

func stringsFromAny(value any) []string {
	out := []string{}
	switch items := value.(type) {
	case []any:
		for _, item := range items {
			text, ok := item.(string)
			if ok {
				out = append(out, text)
			}
		}
	case []string:
		out = append(out, items...)
	}
	return out
}

func stringsAny(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func optionalString(value any) string {
	text, _ := value.(string)
	return text
}

func intFromMap(value any, key string) int {
	body, _ := value.(map[string]any)
	switch item := body[key].(type) {
	case int:
		return item
	case float64:
		return int(item)
	default:
		return 0
	}
}

func validateTaskID(taskID string) error {
	if taskID == "" || len(taskID) > 128 {
		return errors.New("task_id invalid")
	}
	for _, r := range taskID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == ':' || r == '-' {
			continue
		}
		return errors.New("task_id invalid")
	}
	return nil
}

func frameSeconds(frame map[string]any, key string, fallback int) int {
	seconds, ok := frame[key].(float64)
	if !ok {
		return fallback
	}
	return int(seconds)
}

func queueRetryBackoffActive(item map[string]any) bool {
	retryAfterAt := optionalString(item["retry_after_at"])
	if retryAfterAt == "" {
		return false
	}
	retryAfter, err := time.Parse(time.RFC3339Nano, retryAfterAt)
	return err == nil && time.Now().UTC().Before(retryAfter)
}

func queueLeaseExpired(item map[string]any) bool {
	expiresAt, err := time.Parse(time.RFC3339Nano, optionalString(item["lease_expires_at"]))
	if err != nil {
		return true
	}
	return !time.Now().UTC().Before(expiresAt)
}

func copyQueueCarryFields(dst, src map[string]any) {
	for _, key := range []string{"requester_zone_binding", "retry_of", "retry_attempt", "retry_after_at", "resume_checkpoint"} {
		if value, ok := src[key]; ok {
			dst[key] = value
		}
	}
}

func mapsFromAny(value any) []map[string]any {
	if typed, ok := value.([]map[string]any); ok {
		return typed
	}
	items, _ := value.([]any)
	out := []map[string]any{}
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if ok {
			out = append(out, entry)
		}
	}
	return out
}

func hasPrefix(value string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func signBody(key ed25519.PrivateKey, body map[string]any) map[string]any {
	return signBodyWithKey(key, body, "signature")
}

func digestHex(value any) string {
	data, _ := canonicalJSON(value)
	return digestBytesHex(data)
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func digestBytesHex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func signBodyWithKey(key ed25519.PrivateKey, body map[string]any, signatureKey string) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	data, _ := canonicalJSON(body)
	out[signatureKey] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data))
	return out
}

func hasCapability(worker map[string]any, capability string) bool {
	switch items := worker["capabilities"].(type) {
	case []any:
		for _, item := range items {
			if item == capability {
				return true
			}
		}
	case []string:
		for _, item := range items {
			if item == capability {
				return true
			}
		}
	}
	return false
}

func send(conn net.Conn, frame map[string]any) {
	data, _ := json.Marshal(frame)
	fmt.Fprintln(conn, string(data))
}
