package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
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
	Tool         string         `json:"tool,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolCommand  []string       `json:"tool_command,omitempty"`
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

type sendFunc func(map[string]any)

func main() {
	port := flag.String("port", "9090", "listen port")
	wsPort := flag.String("ws-port", "", "optional WebSocket listen port")
	humanPort := flag.String("human-port", "", "optional read-only Human Gateway HTTP port")
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

	if err := serve(*port, *wsPort, *humanPort, *fixturePath, *trustPath, *authorityKeyPath, *workerKeyPath, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(port, wsPort, humanPort, fixturePath, trustPath, authorityKeyPath, workerKeyPath, auditPath string) error {
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
	var wsListener net.Listener
	if wsPort != "" {
		wsListener, err = net.Listen("tcp", "127.0.0.1:"+wsPort)
		if err != nil {
			return err
		}
		go acceptWebSocket(wsListener, fixture, trusted)
	}
	if humanPort != "" {
		humanListener, err := net.Listen("tcp", "127.0.0.1:"+humanPort)
		if err != nil {
			return err
		}
		go serveHumanGateway(humanListener, auditPath)
	}
	if wsPort != "" || humanPort != "" {
		status := map[string]any{"go_fed_discovery": "listening", "port": port}
		if wsPort != "" {
			status["ws_port"] = wsPort
		}
		if humanPort != "" {
			status["human_port"] = humanPort
		}
		data, _ := json.Marshal(status)
		fmt.Println(string(data))
	} else {
		fmt.Println(`{"go_fed_discovery":"listening","port":` + port + `}`)
	}
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
	sendLine := func(frame map[string]any) { send(conn, frame) }
	for scanner.Scan() {
		var frame map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			sendLine(map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return
		}
		if !handleFrame(sendLine, frame, fixture, trusted) {
			return
		}
	}
}

func handleFrame(send sendFunc, frame map[string]any, fixture Fixture, trusted map[string]map[string]any) bool {
	origin, ok := frame["origin_zone"].(map[string]any)
	if !ok {
		send(map[string]any{"type": "FED_TASK_ERROR", "error": "missing origin_zone"})
		return false
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		send(map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
		return false
	}
	switch frame["type"] {
	case "FED_RESOLVE":
		worker := fixture.workerByAlias(fmt.Sprint(frame["alias"]))
		if worker == nil {
			send(map[string]any{"type": "FED_TASK_ERROR", "error": "remote alias not found"})
			return false
		}
		send(map[string]any{
			"type":         "FED_RESOLVE_RESULT",
			"zone":         fixture.Authority,
			"worker":       worker.Descriptor,
			"zone_binding": fixture.zoneBinding(worker),
		})
		send(map[string]any{"type": "FED_RESOLVE_CLOSE", "alias": frame["alias"]})
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
		send(map[string]any{
			"type":       "FED_QUERY_RESULT",
			"zone":       fixture.Authority,
			"capability": frame["capability"],
			"matches":    matches,
		})
		send(map[string]any{"type": "FED_QUERY_CLOSE", "capability": frame["capability"]})
	case "FED_TASK_OPEN":
		worker, task, err := fixture.verifyTaskOpen(frame)
		if err != nil {
			send(map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task); err != nil {
			send(map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return false
		}
	default:
		send(map[string]any{"type": "FED_TASK_ERROR", "error": "unsupported frame"})
		return false
	}
	return true
}

func acceptWebSocket(listener net.Listener, fixture Fixture, trusted map[string]map[string]any) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleWebSocket(conn, fixture, trusted)
	}
}

func handleWebSocket(conn net.Conn, fixture Fixture, trusted map[string]map[string]any) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := websocketHandshake(conn, reader); err != nil {
		return
	}
	sendWS := func(frame map[string]any) {
		data, _ := json.Marshal(frame)
		_ = writeWebSocketText(conn, string(data))
	}
	for {
		text, err := readWebSocketText(reader)
		if err != nil {
			return
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(text), &frame); err != nil {
			sendWS(map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()})
			return
		}
		if !handleFrame(sendWS, frame, fixture, trusted) {
			return
		}
	}
}

func websocketHandshake(conn net.Conn, reader *bufio.Reader) error {
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if index := strings.Index(line, ":"); index >= 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:index]))] = strings.TrimSpace(line[index+1:])
		}
	}
	key := headers["sec-websocket-key"]
	if key == "" {
		return errors.New("missing sec-websocket-key")
	}
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(hash[:])
	_, err := fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	return err
}

func readWebSocketText(reader *bufio.Reader) (string, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	opcode := first & 0x0f
	if opcode == 0x8 {
		return "", io.EOF
	}
	if opcode != 0x1 {
		return "", errors.New("expected websocket text frame")
	}
	masked := second&0x80 != 0
	length := uint64(second & 0x7f)
	if length == 126 {
		var buf [2]byte
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return "", err
		}
		length = uint64(binary.BigEndian.Uint16(buf[:]))
	} else if length == 127 {
		var buf [8]byte
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return "", err
		}
		length = binary.BigEndian.Uint64(buf[:])
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return "", err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return string(payload), nil
}

func writeWebSocketText(conn net.Conn, text string) error {
	payload := []byte(text)
	header := []byte{0x81}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func serveHumanGateway(listener net.Listener, auditPath string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		entries, err := readAuditEntriesOrEmpty(auditPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, renderHumanGateway(entries))
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		entries, err := readAuditEntriesOrEmpty(auditPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
	})
	mux.Handle("/artifacts/", http.StripPrefix("/artifacts/", http.FileServer(http.Dir("artifacts"))))
	_ = http.Serve(listener, mux)
}

func readAuditEntriesOrEmpty(path string) ([]map[string]any, error) {
	entries, err := readAuditEntries(path)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	return entries, err
}

func renderHumanGateway(entries []map[string]any) string {
	events := 0
	receipts := []map[string]any{}
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		switch record["kind"] {
		case "go_fed_event":
			events++
		case "go_fed_receipt":
			receipts = append(receipts, record)
		}
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Agent Space Human Gateway</title><style>
body{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:0;background:#f7f8fa;color:#171a1f}
main{max-width:1120px;margin:0 auto;padding:28px 22px 48px}
header{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;border-bottom:1px solid #d9dee7;padding-bottom:18px;margin-bottom:22px}
h1{font-size:24px;margin:0} h2{font-size:16px;margin:28px 0 10px}.metric{font-size:13px;color:#4c5563}
table{width:100%;border-collapse:collapse;background:white;border:1px solid #d9dee7}th,td{text-align:left;padding:10px;border-bottom:1px solid #e8ebf0;font-size:14px;vertical-align:top}th{background:#eef1f5;font-weight:650}
a{color:#0b5cad;text-decoration:none}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
</style></head><body><main>`)
	b.WriteString(`<header><div><h1>Agent Space Human Gateway</h1><div class="metric">read-only / local proof</div></div><div class="metric">audit entries: `)
	b.WriteString(fmt.Sprint(len(entries)))
	b.WriteString(` · events: `)
	b.WriteString(fmt.Sprint(events))
	b.WriteString(` · receipts: `)
	b.WriteString(fmt.Sprint(len(receipts)))
	b.WriteString(`</div></header>`)
	b.WriteString(`<h2>Receipts</h2><table><thead><tr><th>Task</th><th>Worker</th><th>Artifact</th><th>Events</th></tr></thead><tbody>`)
	if len(receipts) == 0 {
		b.WriteString(`<tr><td colspan="4">No receipts</td></tr>`)
	}
	for _, record := range receipts {
		worker, _ := record["worker"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		artifact := firstString(receipt["artifact_refs"])
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(fmt.Sprint(receipt["task_id"])))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(worker["alias"])))
		b.WriteString(`</td><td>`)
		if artifact != "" {
			b.WriteString(`<a href="/artifacts/`)
			b.WriteString(html.EscapeString(strings.TrimPrefix(artifact, "artifact://local/")))
			b.WriteString(`">`)
			b.WriteString(html.EscapeString(artifact))
			b.WriteString(`</a>`)
		}
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(receipt["event_count"])))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table><h2>Audit</h2><table><thead><tr><th>Index</th><th>Kind</th><th>Hash</th></tr></thead><tbody>`)
	for index, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		b.WriteString(`<tr><td>`)
		b.WriteString(fmt.Sprint(index + 1))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(record["kind"])))
		b.WriteString(`</td><td><code>`)
		b.WriteString(html.EscapeString(fmt.Sprint(entry["hash"])))
		b.WriteString(`</code></td></tr>`)
	}
	b.WriteString(`</tbody></table></main></body></html>`)
	return b.String()
}

func firstString(value any) string {
	switch items := value.(type) {
	case []any:
		if len(items) > 0 {
			return fmt.Sprint(items[0])
		}
	case []string:
		if len(items) > 0 {
			return items[0]
		}
	}
	return ""
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

func (f Fixture) executeTask(send sendFunc, origin map[string]any, worker *Worker, task map[string]any) error {
	taskID := fmt.Sprint(task["task_id"])
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.accepted", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.started", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}

	artifactURI := "artifact://local/" + taskID + "/go-summary.md"
	toolName, artifactText, err := runTool(worker.Profile, task, origin)
	if err != nil {
		return err
	}
	if err := writeArtifact(artifactURI, artifactText); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
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
		"tool":           toolName,
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
	send(map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         receiptRecord["zone"],
		"worker":       receiptRecord["worker"],
		"zone_binding": receiptRecord["zone_binding"],
		"receipt":      receiptRecord["receipt"],
	})
	send(map[string]any{"type": "FED_TASK_CLOSE", "task_id": taskID})
	return nil
}

func runTool(profile WorkerProfile, task, origin map[string]any) (string, string, error) {
	tool := profile.Tool
	if tool == "" {
		tool = "text.echo"
	}
	taskID := fmt.Sprint(task["task_id"])
	intent := fmt.Sprint(task["intent"])
	switch tool {
	case "summarize.mock":
		return tool, "# Go Tool Summary\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nSummary: " + intent + "\n", nil
	case "translate.mock":
		return tool, "# Go Tool Translation\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nTranslation: " + strings.ToUpper(intent) + "\n", nil
	case "external.stdio":
		text, err := runExternalTool(profile, task, origin)
		return tool, text, err
	case "mcp.stdio":
		text, err := runMCPTool(profile, task, origin)
		return tool, text, err
	default:
		return tool, "# Go Tool Output\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nOutput: " + intent + "\n", nil
	}
}

func runExternalTool(profile WorkerProfile, task, origin map[string]any) (string, error) {
	if len(profile.ToolCommand) == 0 {
		return "", errors.New("external.stdio tool_command missing")
	}
	dir, err := os.MkdirTemp("", "agnet-tool-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	input := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
		"tool":    profile.Tool,
	}
	data, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("external tool timed out")
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New("external tool failed: " + message)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		return "", err
	}
	text, ok := result["text"].(string)
	if !ok || text == "" {
		return "", errors.New("external tool text missing")
	}
	return text, nil
}

func runMCPTool(profile WorkerProfile, task, origin map[string]any) (string, error) {
	if len(profile.ToolCommand) == 0 {
		return "", errors.New("mcp.stdio tool_command missing")
	}
	toolName := profile.ToolName
	if toolName == "" {
		return "", errors.New("mcp.stdio tool_name missing")
	}
	dir, err := os.MkdirTemp("", "agnet-mcp-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(stdout)
	writeRPC := func(message map[string]any) error {
		data, err := json.Marshal(message)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdin, string(data))
		return err
	}
	if err := writeRPC(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-11-25",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "agnet-go", "version": "v3.7"},
		},
	}); err != nil {
		return "", err
	}
	if _, err := readRPCResponse(scanner, 1); err != nil {
		return "", err
	}
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		return "", err
	}
	args := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
	}
	if err := writeRPC(map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params":  map[string]any{"name": toolName, "arguments": args},
	}); err != nil {
		return "", err
	}
	response, err := readRPCResponse(scanner, 2)
	if err != nil {
		return "", err
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New("mcp tool failed: " + message)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", errors.New("mcp tool timed out")
	}
	return mcpText(response)
}

func readRPCResponse(scanner *bufio.Scanner, id float64) (map[string]any, error) {
	for scanner.Scan() {
		var message map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return nil, err
		}
		if message["id"] == id {
			if message["error"] != nil {
				return nil, errors.New("mcp error: " + fmt.Sprint(message["error"]))
			}
			return message, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("mcp response missing")
}

func mcpText(response map[string]any) (string, error) {
	result, _ := response["result"].(map[string]any)
	content, _ := result["content"].([]any)
	for _, item := range content {
		entry, _ := item.(map[string]any)
		if entry["type"] == "text" {
			text, _ := entry["text"].(string)
			if text != "" {
				return text, nil
			}
		}
	}
	return "", errors.New("mcp text content missing")
}

func (f Fixture) sendTaskEvent(send sendFunc, event map[string]any) error {
	if err := f.appendAudit(map[string]any{"kind": "go_fed_event", "event": event}); err != nil {
		return err
	}
	send(map[string]any{"type": "FED_TASK_EVENT", "event": event})
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
