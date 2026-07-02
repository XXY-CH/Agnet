package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Fixture struct {
	Authority           map[string]any     `json:"authority"`
	WorkerProfile       WorkerProfile      `json:"worker_profile"`
	Worker              map[string]any     `json:"-"`
	Credential          map[string]any     `json:"credential"`
	AuthorityPrivateKey ed25519.PrivateKey `json:"-"`
	WorkerPrivateKey    ed25519.PrivateKey `json:"-"`
}

type WorkerProfile struct {
	Alias        string         `json:"alias"`
	Transports   []string       `json:"transports"`
	Capabilities []string       `json:"capabilities"`
	Policy       map[string]any `json:"policy"`
}

type TrustStore struct {
	Zones []map[string]any `json:"zones"`
}

func main() {
	port := flag.String("port", "9090", "listen port")
	fixturePath := flag.String("fixture", "test-vectors/asp-v1.5-capability-credential.json", "signed descriptor fixture")
	trustPath := flag.String("trusted", "state/go-fed-trusted-zones.json", "trusted origin zones")
	authorityKeyPath := flag.String("authority-key", "state/keys/go-fed-authority.seed", "authority seed key file")
	workerKeyPath := flag.String("worker-key", "state/keys/go-fed-worker.seed", "worker seed key file")
	flag.Parse()

	if err := serve(*port, *fixturePath, *trustPath, *authorityKeyPath, *workerKeyPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(port, fixturePath, trustPath, authorityKeyPath, workerKeyPath string) error {
	authorityKey, err := loadPrivateKey(authorityKeyPath, "authority")
	if err != nil {
		return err
	}
	workerKey, err := loadPrivateKey(workerKeyPath, "worker")
	if err != nil {
		return err
	}
	fixture, err := loadFixture(fixturePath, authorityKey, workerKey)
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
				"zone_binding": fixture.zoneBinding(),
			})
			send(conn, map[string]any{"type": "FED_RESOLVE_CLOSE", "alias": frame["alias"]})
		case "FED_QUERY":
			matches := []any{}
			if hasCapability(fixture.Worker, fmt.Sprint(frame["capability"])) {
				matches = append(matches, map[string]any{
					"worker":       fixture.Worker,
					"zone_binding": fixture.zoneBinding(),
					"credentials":  []any{fixture.capabilityCredential(fmt.Sprint(frame["capability"]))},
				})
			}
			send(conn, map[string]any{
				"type":       "FED_QUERY_RESULT",
				"zone":       fixture.Authority,
				"capability": frame["capability"],
				"matches":    matches,
			})
			send(conn, map[string]any{"type": "FED_QUERY_CLOSE", "capability": frame["capability"]})
		case "FED_TASK_OPEN":
			task, err := fixture.verifyTaskOpen(frame)
			if err != nil {
				send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
				return
			}
			if err := fixture.executeTask(conn, origin, task); err != nil {
				send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
				return
			}
		default:
			send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": "unsupported frame"})
			return
		}
	}
}

func loadFixture(path string, authorityKey, workerKey ed25519.PrivateKey) (Fixture, error) {
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
	fixture.AuthorityPrivateKey = authorityKey
	fixture.WorkerPrivateKey = workerKey
	if err := fixture.verifyAuthoritySeed(); err != nil {
		return Fixture{}, err
	}
	worker, err := fixture.workerDescriptor()
	if err != nil {
		return Fixture{}, err
	}
	fixture.Worker = worker
	if err := verifyAgentDescriptor(fixture.Worker); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}

func loadPrivateKey(path, label string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return privateKeyFromSeedHex(strings.TrimSpace(string(data)), label)
}

func privateKeyFromSeedHex(seedHex, label string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New(label + " seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (f Fixture) verifyAuthoritySeed() error {
	publicKey := f.AuthorityPrivateKey.Public().(ed25519.PublicKey)
	encoded, _, err := publicKeySPKI(publicKey)
	if err != nil {
		return err
	}
	if encoded != f.Authority["public_key_spki"] {
		return errors.New("authority seed does not match authority descriptor")
	}
	return nil
}

func (f Fixture) workerDescriptor() (map[string]any, error) {
	if f.WorkerProfile.Alias == "" {
		return nil, errors.New("worker profile alias missing")
	}
	if len(f.WorkerProfile.Transports) == 0 {
		return nil, errors.New("worker profile transports missing")
	}
	if len(f.WorkerProfile.Capabilities) == 0 {
		return nil, errors.New("worker profile capabilities missing")
	}
	publicKey := f.WorkerPrivateKey.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	policy := f.WorkerProfile.Policy
	if policy == nil {
		policy = map[string]any{}
	}
	body := map[string]any{
		"alias":           f.WorkerProfile.Alias,
		"aid":             aidFromSPKI(der),
		"public_key_spki": encoded,
		"transports":      f.WorkerProfile.Transports,
		"capabilities":    f.WorkerProfile.Capabilities,
		"policy":          policy,
	}
	return signBodyWithKey(f.WorkerPrivateKey, body, "descriptor_signature"), nil
}

func (f Fixture) zoneBinding() map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"zone":  f.Authority["zid"],
		"alias": f.Worker["alias"],
		"aid":   f.Worker["aid"],
	})
}

func (f Fixture) capabilityCredential(capability string) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"issuer":     f.Authority["zid"],
		"subject":    f.Worker["aid"],
		"capability": capability,
		"claims":     f.Credential["claims"],
	})
}

func (f Fixture) verifyTaskOpen(frame map[string]any) (map[string]any, error) {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, errors.New("missing requester")
	}
	if err := verifyAgentDescriptor(requester); err != nil {
		return nil, err
	}
	task, ok := frame["task"].(map[string]any)
	if !ok {
		return nil, errors.New("missing task")
	}
	if task["from"] != requester["aid"] {
		return nil, errors.New("task sender does not match requester descriptor")
	}
	if task["to"] != f.Worker["alias"] {
		return nil, errors.New("task target does not match worker alias")
	}
	requesterKey, _, err := publicKey(requester)
	if err != nil {
		return nil, err
	}
	if err := verifyMapSignature(requesterKey, task, "signature"); err != nil {
		return nil, errors.New("task signature verification failed")
	}
	if err := enforcePolicy(f.Worker, task); err != nil {
		return nil, err
	}
	return task, nil
}

func (f Fixture) executeTask(conn net.Conn, origin, task map[string]any) error {
	taskID := fmt.Sprint(task["task_id"])
	sendTaskEvent(conn, map[string]any{"type": "task.accepted", "task_id": taskID, "by": f.Worker["aid"], "zone": f.Authority["zid"]})
	sendTaskEvent(conn, map[string]any{"type": "task.started", "task_id": taskID, "by": f.Worker["aid"], "zone": f.Authority["zid"]})

	artifactURI := "artifact://local/" + taskID + "/go-summary.md"
	if err := writeArtifact(artifactURI, "# Go Federated Summary\n\nCompleted "+taskID+" from "+fmt.Sprint(origin["zid"])+".\n"); err != nil {
		return err
	}
	sendTaskEvent(conn, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI})
	sendTaskEvent(conn, map[string]any{"type": "task.completed", "task_id": taskID, "by": f.Worker["aid"], "zone": f.Authority["zid"]})

	receipt := map[string]any{
		"task_id":        taskID,
		"from":           task["from"],
		"origin_zone":    origin["zid"],
		"executing_zone": f.Authority["zid"],
		"to":             f.Worker["aid"],
		"artifact_refs":  []string{artifactURI},
		"event_count":    float64(4),
		"approvals":      []string{},
	}
	send(conn, map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         f.Authority,
		"worker":       f.Worker,
		"zone_binding": f.zoneBinding(),
		"receipt":      signBody(f.WorkerPrivateKey, receipt),
	})
	send(conn, map[string]any{"type": "FED_TASK_CLOSE", "task_id": taskID})
	return nil
}

func sendTaskEvent(conn net.Conn, event map[string]any) {
	send(conn, map[string]any{"type": "FED_TASK_EVENT", "event": event})
}

func writeArtifact(uri, text string) error {
	const prefix = "artifact://local/"
	if !strings.HasPrefix(uri, prefix) {
		return errors.New("unsupported artifact uri: " + uri)
	}
	path := filepath.Join("artifacts", strings.TrimPrefix(uri, prefix))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func enforcePolicy(worker, task map[string]any) error {
	policy, _ := worker["policy"].(map[string]any)
	scope, _ := task["scope"].(map[string]any)
	if scope["network"] == true && policy["allow_network"] != true {
		return errors.New("policy denied network access")
	}
	for _, target := range stringsFromAny(scope["write"]) {
		if !hasPrefix(target, stringsFromAny(policy["write_prefixes"])) {
			return errors.New("policy denied write scope: " + target)
		}
	}
	return nil
}

func stringsFromAny(value any) []string {
	items, _ := value.([]any)
	out := []string{}
	for _, item := range items {
		text, ok := item.(string)
		if ok {
			out = append(out, text)
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

func signBodyWithKey(key ed25519.PrivateKey, body map[string]any, signatureKey string) map[string]any {
	out := map[string]any{}
	for k, v := range body {
		out[k] = v
	}
	data, _ := json.Marshal(body)
	out[signatureKey] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, data))
	return out
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

func publicKeySPKI(key ed25519.PublicKey) (string, []byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(der), der, nil
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
