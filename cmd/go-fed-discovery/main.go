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
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Fixture struct {
	Authority           map[string]any     `json:"authority"`
	WorkerProfile       WorkerProfile      `json:"worker_profile"`
	WorkerProfiles      []WorkerProfile    `json:"worker_profiles"`
	Workers             []Worker           `json:"-"`
	Credential          map[string]any     `json:"credential"`
	AuthorityPrivateKey ed25519.PrivateKey `json:"-"`
	Audit               *AuditLog          `json:"-"`
}

type WorkerProfile struct {
	KeyFile      string         `json:"key_file,omitempty"`
	Alias        string         `json:"alias"`
	Transports   []string       `json:"transports"`
	Capabilities []string       `json:"capabilities"`
	Policy       map[string]any `json:"policy"`
}

type Worker struct {
	Profile    WorkerProfile
	Descriptor map[string]any
	PrivateKey ed25519.PrivateKey
}

type TrustStore struct {
	Zones []map[string]any `json:"zones"`
}

type AuditLog struct {
	Path string
	Head string
	mu   sync.Mutex
}

func main() {
	port := flag.String("port", "9090", "listen port")
	fixturePath := flag.String("fixture", "test-vectors/asp-v1.5-capability-credential.json", "signed descriptor fixture")
	trustPath := flag.String("trusted", "state/go-fed-trusted-zones.json", "trusted origin zones")
	authorityKeyPath := flag.String("authority-key", "state/keys/go-fed-authority.seed", "authority seed key file")
	workerKeyPath := flag.String("worker-key", "state/keys/go-fed-worker.seed", "worker seed key file")
	auditPath := flag.String("audit", "state/go-fed-audit.log", "audit JSONL file")
	verifyAudit := flag.Bool("verify-audit", false, "verify audit JSONL file and exit")
	flag.Parse()

	if *verifyAudit {
		if err := verifyAuditFile(*auditPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(`{"go_audit_verify":"ok"}`)
		return
	}

	if err := serve(*port, *fixturePath, *trustPath, *authorityKeyPath, *workerKeyPath, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(port, fixturePath, trustPath, authorityKeyPath, workerKeyPath, auditPath string) error {
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
	audit, err := openAuditLog(auditPath)
	if err != nil {
		return err
	}
	fixture.Audit = audit
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
			worker := fixture.workerByAlias(fmt.Sprint(frame["alias"]))
			if worker == nil {
				send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": "remote alias not found"})
				return
			}
			send(conn, map[string]any{
				"type":         "FED_RESOLVE_RESULT",
				"zone":         fixture.Authority,
				"worker":       worker.Descriptor,
				"zone_binding": fixture.zoneBinding(worker),
			})
			send(conn, map[string]any{"type": "FED_RESOLVE_CLOSE", "alias": frame["alias"]})
		case "FED_QUERY":
			matches := []any{}
			capability := fmt.Sprint(frame["capability"])
			for _, worker := range fixture.workersByCapability(capability) {
				matches = append(matches, map[string]any{
					"worker":       worker.Descriptor,
					"zone_binding": fixture.zoneBinding(&worker),
					"credentials":  []any{fixture.capabilityCredential(&worker, capability)},
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
			worker, task, err := fixture.verifyTaskOpen(frame)
			if err != nil {
				send(conn, map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
				return
			}
			if err := fixture.executeTask(conn, origin, worker, task); err != nil {
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
	if err := fixture.verifyAuthoritySeed(); err != nil {
		return Fixture{}, err
	}
	workers, err := fixture.loadWorkers(workerKey)
	if err != nil {
		return Fixture{}, err
	}
	fixture.Workers = workers
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

func (f Fixture) loadWorkers(defaultKey ed25519.PrivateKey) ([]Worker, error) {
	profiles := f.WorkerProfiles
	if len(profiles) == 0 {
		profiles = []WorkerProfile{f.WorkerProfile}
	}
	workers := []Worker{}
	seen := map[string]bool{}
	for _, profile := range profiles {
		key := defaultKey
		var err error
		if profile.KeyFile != "" {
			key, err = loadPrivateKey(profile.KeyFile, "worker")
			if err != nil {
				return nil, err
			}
		}
		descriptor, err := workerDescriptor(profile, key)
		if err != nil {
			return nil, err
		}
		if seen[profile.Alias] {
			return nil, errors.New("duplicate worker alias: " + profile.Alias)
		}
		seen[profile.Alias] = true
		if err := verifyAgentDescriptor(descriptor); err != nil {
			return nil, err
		}
		workers = append(workers, Worker{Profile: profile, Descriptor: descriptor, PrivateKey: key})
	}
	return workers, nil
}

func workerDescriptor(profile WorkerProfile, key ed25519.PrivateKey) (map[string]any, error) {
	if profile.Alias == "" {
		return nil, errors.New("worker profile alias missing")
	}
	if len(profile.Transports) == 0 {
		return nil, errors.New("worker profile transports missing")
	}
	if len(profile.Capabilities) == 0 {
		return nil, errors.New("worker profile capabilities missing")
	}
	publicKey := key.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	policy := profile.Policy
	if policy == nil {
		policy = map[string]any{}
	}
	body := map[string]any{
		"alias":           profile.Alias,
		"aid":             aidFromSPKI(der),
		"public_key_spki": encoded,
		"transports":      profile.Transports,
		"capabilities":    profile.Capabilities,
		"policy":          policy,
	}
	return signBodyWithKey(key, body, "descriptor_signature"), nil
}

func (f Fixture) workerByAlias(alias string) *Worker {
	for i := range f.Workers {
		if f.Workers[i].Descriptor["alias"] == alias {
			return &f.Workers[i]
		}
	}
	return nil
}

func (f Fixture) workersByCapability(capability string) []Worker {
	workers := []Worker{}
	for _, worker := range f.Workers {
		if hasCapability(worker.Descriptor, capability) {
			workers = append(workers, worker)
		}
	}
	return workers
}

func (f Fixture) zoneBinding(worker *Worker) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"zone":  f.Authority["zid"],
		"alias": worker.Descriptor["alias"],
		"aid":   worker.Descriptor["aid"],
	})
}

func (f Fixture) capabilityCredential(worker *Worker, capability string) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"issuer":     f.Authority["zid"],
		"subject":    worker.Descriptor["aid"],
		"capability": capability,
		"claims":     f.Credential["claims"],
	})
}

func (f Fixture) verifyTaskOpen(frame map[string]any) (*Worker, map[string]any, error) {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("missing requester")
	}
	if err := verifyAgentDescriptor(requester); err != nil {
		return nil, nil, err
	}
	task, ok := frame["task"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("missing task")
	}
	if task["from"] != requester["aid"] {
		return nil, nil, errors.New("task sender does not match requester descriptor")
	}
	worker := f.workerByAlias(fmt.Sprint(task["to"]))
	if worker == nil {
		return nil, nil, errors.New("task target does not match worker alias")
	}
	requesterKey, _, err := publicKey(requester)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyMapSignature(requesterKey, task, "signature"); err != nil {
		return nil, nil, errors.New("task signature verification failed")
	}
	if err := enforcePolicy(worker.Descriptor, task); err != nil {
		return nil, nil, err
	}
	return worker, task, nil
}

func (f Fixture) executeTask(conn net.Conn, origin map[string]any, worker *Worker, task map[string]any) error {
	taskID := fmt.Sprint(task["task_id"])
	if err := f.sendTaskEvent(conn, map[string]any{"type": "task.accepted", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(conn, map[string]any{"type": "task.started", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}

	artifactURI := "artifact://local/" + taskID + "/go-summary.md"
	if err := writeArtifact(artifactURI, "# Go Federated Summary\n\nCompleted "+taskID+" from "+fmt.Sprint(origin["zid"])+".\n"); err != nil {
		return err
	}
	if err := f.sendTaskEvent(conn, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(conn, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}

	receipt := map[string]any{
		"task_id":        taskID,
		"from":           task["from"],
		"origin_zone":    origin["zid"],
		"executing_zone": f.Authority["zid"],
		"to":             worker.Descriptor["aid"],
		"artifact_refs":  []string{artifactURI},
		"event_count":    float64(4),
		"approvals":      []string{},
	}
	signedReceipt := signBody(worker.PrivateKey, receipt)
	receiptRecord := map[string]any{
		"kind":         "go_fed_receipt",
		"zone":         f.Authority,
		"worker":       worker.Descriptor,
		"zone_binding": f.zoneBinding(worker),
		"receipt":      signedReceipt,
	}
	if err := f.appendAudit(receiptRecord); err != nil {
		return err
	}
	send(conn, map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         receiptRecord["zone"],
		"worker":       receiptRecord["worker"],
		"zone_binding": receiptRecord["zone_binding"],
		"receipt":      receiptRecord["receipt"],
	})
	send(conn, map[string]any{"type": "FED_TASK_CLOSE", "task_id": taskID})
	return nil
}

func (f Fixture) sendTaskEvent(conn net.Conn, event map[string]any) error {
	if err := f.appendAudit(map[string]any{"kind": "go_fed_event", "event": event}); err != nil {
		return err
	}
	send(conn, map[string]any{"type": "FED_TASK_EVENT", "event": event})
	return nil
}

func (f Fixture) appendAudit(record map[string]any) error {
	if f.Audit == nil {
		return nil
	}
	return f.Audit.Append(record)
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

const auditZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func openAuditLog(path string) (*AuditLog, error) {
	audit := &AuditLog{Path: path, Head: auditZeroHash}
	entries, err := readAuditEntries(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return audit, nil
		}
		return nil, err
	}
	prev := auditZeroHash
	for _, entry := range entries {
		if err := verifyAuditEntry(entry, prev); err != nil {
			return nil, err
		}
		prev = fmt.Sprint(entry["hash"])
	}
	audit.Head = prev
	return audit, nil
}

func (a *AuditLog) Append(record map[string]any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, err := auditEntry(a.Head, record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(file, string(data)); err != nil {
		return err
	}
	a.Head = fmt.Sprint(entry["hash"])
	return nil
}

func verifyAuditFile(path string) error {
	entries, err := readAuditEntries(path)
	if err != nil {
		return err
	}
	prev := auditZeroHash
	for _, entry := range entries {
		if err := verifyAuditEntry(entry, prev); err != nil {
			return err
		}
		record, ok := entry["record"].(map[string]any)
		if !ok {
			return errors.New("audit record missing")
		}
		if record["kind"] == "go_fed_receipt" {
			if err := verifyReceiptRecord(record); err != nil {
				return err
			}
		}
		prev = fmt.Sprint(entry["hash"])
	}
	return nil
}

func readAuditEntries(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := []map[string]any{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return out, nil
}

func verifyAuditEntry(entry map[string]any, prev string) error {
	record, ok := entry["record"].(map[string]any)
	if !ok {
		return errors.New("audit record missing")
	}
	if entry["prev_hash"] != prev {
		return errors.New("audit prev_hash mismatch")
	}
	expected, err := auditEntry(prev, record)
	if err != nil {
		return err
	}
	if entry["hash"] != expected["hash"] {
		return errors.New("audit hash mismatch")
	}
	return nil
}

func auditEntry(prev string, record map[string]any) (map[string]any, error) {
	body := map[string]any{"prev_hash": prev, "record": record}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(data)
	return map[string]any{"prev_hash": prev, "record": record, "hash": hex.EncodeToString(hash[:])}, nil
}

func verifyReceiptRecord(record map[string]any) error {
	zone, ok := record["zone"].(map[string]any)
	if !ok {
		return errors.New("receipt zone missing")
	}
	worker, ok := record["worker"].(map[string]any)
	if !ok {
		return errors.New("receipt worker missing")
	}
	binding, ok := record["zone_binding"].(map[string]any)
	if !ok {
		return errors.New("receipt zone_binding missing")
	}
	receipt, ok := record["receipt"].(map[string]any)
	if !ok {
		return errors.New("receipt missing")
	}
	if err := verifyZoneDescriptor(zone); err != nil {
		return err
	}
	workerKey, _, err := publicKey(worker)
	if err != nil {
		return err
	}
	if err := verifyAgentDescriptor(worker); err != nil {
		return err
	}
	if err := verifyZoneBinding(zone, binding, worker); err != nil {
		return err
	}
	if receipt["executing_zone"] != zone["zid"] {
		return errors.New("receipt executing_zone mismatch")
	}
	if receipt["to"] != worker["aid"] {
		return errors.New("receipt worker mismatch")
	}
	if err := verifyMapSignature(workerKey, receipt, "signature"); err != nil {
		return errors.New("receipt signature verification failed")
	}
	return nil
}

func verifyZoneBinding(zone, binding, worker map[string]any) error {
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	expected := map[string]any{"zone": zone["zid"], "alias": worker["alias"], "aid": worker["aid"]}
	if binding["zone"] != expected["zone"] || binding["alias"] != expected["alias"] || binding["aid"] != expected["aid"] {
		return errors.New("zone binding mismatch")
	}
	if err := verifyMapSignature(zoneKey, binding, "signature"); err != nil {
		return errors.New("zone binding signature verification failed")
	}
	return nil
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
