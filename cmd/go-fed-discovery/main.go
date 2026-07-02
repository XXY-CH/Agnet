package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
)

type Fixture struct {
	Authority   map[string]any `json:"authority"`
	Worker      map[string]any `json:"worker"`
	ZoneBinding map[string]any `json:"zone_binding"`
	Credential  map[string]any `json:"credential"`
}

type TrustStore struct {
	Zones []map[string]any `json:"zones"`
}

func main() {
	port := flag.String("port", "9090", "listen port")
	fixturePath := flag.String("fixture", "test-vectors/asp-v1.5-capability-credential.json", "signed descriptor fixture")
	trustPath := flag.String("trusted", "state/go-fed-trusted-zones.json", "trusted origin zones")
	flag.Parse()

	if err := serve(*port, *fixturePath, *trustPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(port, fixturePath, trustPath string) error {
	fixture, err := loadFixture(fixturePath)
	if err != nil {
		return err
	}
	trusted, err := loadTrustedZones(trustPath)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return err
	}
	fmt.Println(`{"go_fed_discovery":"listening","port":` + port + `}`)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handle(conn, fixture, trusted)
	}
}

func handle(conn net.Conn, fixture Fixture, trusted map[string]map[string]any) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var frame map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return
		}
		origin, ok := frame["origin_zone"].(map[string]any)
		if !ok {
			send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": "missing origin_zone"})
			return
		}
		if err := verifyTrustedZone(origin, trusted); err != nil {
			send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return
		}
		switch frame["type"] {
		case "FED_RESOLVE":
			if frame["alias"] != fixture.Worker["alias"] {
				send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": "remote alias not found"})
				return
			}
			send(conn, map[string]any{
				"type":         "FED_RESOLVE_RESULT",
				"zone":         fixture.Authority,
				"worker":       fixture.Worker,
				"zone_binding": fixture.ZoneBinding,
			})
			send(conn, map[string]any{"type": "FED_RESOLVE_CLOSE", "alias": frame["alias"]})
		case "FED_QUERY":
			matches := []any{}
			if hasCapability(fixture.Worker, fmt.Sprint(frame["capability"])) {
				matches = append(matches, map[string]any{
					"worker":       fixture.Worker,
					"zone_binding": fixture.ZoneBinding,
					"credentials":  []any{fixture.Credential},
				})
			}
			send(conn, map[string]any{
				"type":       "FED_QUERY_RESULT",
				"zone":       fixture.Authority,
				"capability": frame["capability"],
				"matches":    matches,
			})
			send(conn, map[string]any{"type": "FED_QUERY_CLOSE", "capability": frame["capability"]})
		default:
			send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": "unsupported frame"})
			return
		}
	}
}

func loadFixture(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, err
	}
	var fixture Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		return Fixture{}, err
	}
	if err := verifyZoneDescriptor(fixture.Authority); err != nil {
		return Fixture{}, err
	}
	if err := verifyAgentDescriptor(fixture.Worker); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}

func loadTrustedZones(path string) (map[string]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var store TrustStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	out := map[string]map[string]any{}
	for _, zone := range store.Zones {
		if err := verifyZoneDescriptor(zone); err != nil {
			return nil, err
		}
		out[fmt.Sprint(zone["zid"])] = zone
	}
	return out, nil
}

func verifyTrustedZone(zone map[string]any, trusted map[string]map[string]any) error {
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	known := trusted[fmt.Sprint(zone["zid"])]
	if known == nil || known["public_key_spki"] != zone["public_key_spki"] {
		return errors.New("untrusted zone: " + fmt.Sprint(zone["zid"]))
	}
	return nil
}

func verifyZoneDescriptor(zone map[string]any) error {
	key, der, err := publicKey(zone)
	if err != nil {
		return err
	}
	if zidFromSPKI(der) != zone["zid"] {
		return errors.New("zone id mismatch")
	}
	return verifyMapSignature(key, zone, "zone_signature")
}

func verifyAgentDescriptor(agent map[string]any) error {
	key, der, err := publicKey(agent)
	if err != nil {
		return err
	}
	if aidFromSPKI(der) != agent["aid"] {
		return errors.New("agent id mismatch")
	}
	return verifyMapSignature(key, agent, "descriptor_signature")
}

func publicKey(value map[string]any) (ed25519.PublicKey, []byte, error) {
	encoded, ok := value["public_key_spki"].(string)
	if !ok {
		return nil, nil, errors.New("missing public_key_spki")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("expected ed25519 public key")
	}
	return key, der, nil
}

func aidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-agent-id-v1\x00"))
	hash.Write(der)
	return "aid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func zidFromSPKI(der []byte) string {
	hash := sha256.New()
	hash.Write([]byte("asp-zone-id-v1\x00"))
	hash.Write(der)
	return "zid:ed25519:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func verifyMapSignature(key ed25519.PublicKey, value map[string]any, signatureKey string) error {
	signature, ok := value[signatureKey].(string)
	if !ok {
		return errors.New("missing " + signatureKey)
	}
	body := map[string]any{}
	for k, v := range value {
		if k != signatureKey {
			body[k] = v
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, decoded) {
		return errors.New("signature verification failed")
	}
	return nil
}

func hasCapability(worker map[string]any, capability string) bool {
	items, _ := worker["capabilities"].([]any)
	for _, item := range items {
		if item == capability {
			return true
		}
	}
	return false
}

func send(conn net.Conn, frame map[string]any) {
	data, _ := json.Marshal(frame)
	fmt.Fprintln(conn, string(data))
}
