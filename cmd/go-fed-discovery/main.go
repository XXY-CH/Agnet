package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	TaskStateDir        string             `json:"-"`
	Runtime             *TaskRuntime       `json:"-"`
}

type WorkerProfile struct {
	KeyFile      string         `json:"key_file,omitempty"`
	Alias        string         `json:"alias"`
	Tool         string         `json:"tool,omitempty"`
	ToolName     string         `json:"tool_name,omitempty"`
	ToolCommand  []string       `json:"tool_command,omitempty"`
	SandboxClaim string         `json:"sandbox_claim,omitempty"`
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

type TaskRuntime struct {
	mu        sync.Mutex
	running   map[string]context.CancelFunc
	cancelled map[string]bool
}

type sendFunc func(map[string]any)

type Session struct {
	ID            string
	Challenge     string
	PeerZID       string
	Authenticated bool
}

type codedError interface {
	error
	Code() string
}

type policyError struct {
	code    string
	message string
}

func (e policyError) Error() string { return e.message }
func (e policyError) Code() string  { return e.code }

func taskErrorFrame(err error) map[string]any {
	frame := map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()}
	if coded, ok := err.(codedError); ok {
		frame["code"] = coded.Code()
	}
	return frame
}

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
	fixture.TaskStateDir = strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-tasks"
	fixture.Runtime = &TaskRuntime{running: map[string]context.CancelFunc{}, cancelled: map[string]bool{}}
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
	session := &Session{}
	sendLine := func(frame map[string]any) { send(conn, frame) }
	for scanner.Scan() {
		var frame map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
			sendLine(taskErrorFrame(err))
			return
		}
		if !handleFrame(sendLine, frame, fixture, trusted, session) {
			return
		}
	}
}

func handleFrame(send sendFunc, frame map[string]any, fixture Fixture, trusted map[string]map[string]any, session *Session) bool {
	switch frame["type"] {
	case "HELLO":
		if err := handleHello(send, frame, fixture, trusted, session); err != nil {
			send(taskErrorFrame(err))
			return false
		}
		return true
	case "AUTH":
		if err := handleAuth(send, frame, fixture, trusted, session); err != nil {
			send(taskErrorFrame(err))
			return false
		}
		return true
	}
	if !session.Authenticated {
		send(taskErrorFrame(errors.New("session not authenticated")))
		return false
	}
	origin, ok := frame["origin_zone"].(map[string]any)
	if !ok {
		send(taskErrorFrame(errors.New("missing origin_zone")))
		return false
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		send(taskErrorFrame(err))
		return false
	}
	if fmt.Sprint(origin["zid"]) != session.PeerZID {
		send(taskErrorFrame(errors.New("session origin mismatch")))
		return false
	}
	switch frame["type"] {
	case "FED_RESOLVE":
		worker := fixture.workerByAlias(fmt.Sprint(frame["alias"]))
		if worker == nil {
			send(taskErrorFrame(errors.New("remote alias not found")))
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
			credential := fixture.capabilityCredential(&worker, capability)
			matches = append(matches, map[string]any{
				"worker":              worker.Descriptor,
				"zone_binding":        fixture.zoneBinding(&worker),
				"credentials":         []any{credential},
				"credential_statuses": []any{fixture.credentialStatus(credential, "active")},
			})
		}
		send(map[string]any{
			"type":       "FED_QUERY_RESULT",
			"zone":       fixture.Authority,
			"capability": frame["capability"],
			"matches":    matches,
		})
		send(map[string]any{"type": "FED_QUERY_CLOSE", "capability": frame["capability"]})
	case "FED_AUDIT_QUERY":
		record, err := fixture.auditProof(fmt.Sprint(frame["task_id"]))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{
			"type":         "FED_AUDIT_RESULT",
			"zone":         record["zone"],
			"worker":       record["worker"],
			"zone_binding": record["zone_binding"],
			"receipt":      record["receipt"],
			"task_id":      frame["task_id"],
		})
		send(map[string]any{"type": "FED_AUDIT_CLOSE", "task_id": frame["task_id"]})
	case "FED_TASK_OPEN":
		worker, task, err := fixture.verifyTaskOpen(frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, nil, nil); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_RESUME":
		worker, task, err := fixture.verifyTaskOpen(frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		checkpointID := fmt.Sprint(frame["checkpoint_id"])
		if checkpointID == "" || checkpointID == "<nil>" {
			send(taskErrorFrame(errors.New("resume checkpoint_id missing")))
			return false
		}
		if err := fixture.requireCheckpoint(checkpointID); err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, checkpointID, nil); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_RETRY":
		worker, task, err := fixture.verifyTaskOpen(frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		retryOf := fmt.Sprint(frame["retry_of"])
		if retryOf == "" || retryOf == "<nil>" {
			send(taskErrorFrame(errors.New("retry_of missing")))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, nil, retryOf); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_CANCEL":
		worker, requester, cancel, err := fixture.verifyTaskCancel(frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.cancelTask(send, origin, worker, requester, cancel); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	default:
		send(taskErrorFrame(errors.New("unsupported frame")))
		return false
	}
	return true
}

func (f Fixture) auditProof(taskID string) (map[string]any, error) {
	if f.Audit == nil {
		return nil, errors.New("audit log unavailable")
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if err != nil {
		return nil, err
	}
	// ponytail: linear scan is enough for local v4.5 proof; add an index when remote audit query has real volume.
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		if receipt["task_id"] == taskID {
			return record, nil
		}
	}
	return nil, errors.New("audit proof not found: " + taskID)
}

func (f Fixture) requireCheckpoint(checkpointID string) error {
	if f.Audit == nil {
		return errors.New("audit log unavailable")
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("resume checkpoint not found: " + checkpointID)
	}
	if err != nil {
		return err
	}
	// ponytail: linear scan keeps resume evidence honest; add an index when checkpoint lookup has real volume.
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		event, _ := record["event"].(map[string]any)
		checkpoint, _ := event["checkpoint"].(map[string]any)
		if checkpoint["checkpoint_id"] == checkpointID {
			return nil
		}
		receipt, _ := record["receipt"].(map[string]any)
		for _, checkpoint := range mapsFromAny(receipt["checkpoints"]) {
			if checkpoint["checkpoint_id"] == checkpointID {
				return nil
			}
		}
	}
	return errors.New("resume checkpoint not found: " + checkpointID)
}

func handleHello(send sendFunc, frame map[string]any, fixture Fixture, trusted map[string]map[string]any, session *Session) error {
	origin, ok := frame["origin_zone"].(map[string]any)
	if !ok {
		return errors.New("missing origin_zone")
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		return err
	}
	id, err := randomB64URL(16)
	if err != nil {
		return err
	}
	challenge, err := randomB64URL(32)
	if err != nil {
		return err
	}
	session.ID = "session:" + id
	session.Challenge = challenge
	session.PeerZID = fmt.Sprint(origin["zid"])
	session.Authenticated = false
	send(map[string]any{"type": "HELLO", "zone": fixture.Authority, "session_id": session.ID, "challenge": session.Challenge})
	return nil
}

func handleAuth(send sendFunc, frame map[string]any, fixture Fixture, trusted map[string]map[string]any, session *Session) error {
	origin, ok := frame["origin_zone"].(map[string]any)
	if !ok {
		return errors.New("missing origin_zone")
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		return err
	}
	if fmt.Sprint(origin["zid"]) != session.PeerZID {
		return errors.New("session origin mismatch")
	}
	auth, ok := frame["auth"].(map[string]any)
	if !ok {
		return errors.New("missing auth")
	}
	body := sessionAuthBody(session.ID, session.Challenge, session.PeerZID, fmt.Sprint(fixture.Authority["zid"]))
	for key, value := range body {
		if auth[key] != value {
			return errors.New("session auth body mismatch")
		}
	}
	originKey, _, err := publicKey(origin)
	if err != nil {
		return err
	}
	if err := verifyMapSignature(originKey, auth, "auth_signature"); err != nil {
		return errors.New("session auth signature verification failed")
	}
	session.Authenticated = true
	send(map[string]any{"type": "AUTH_OK", "session_id": session.ID})
	return nil
}

func sessionAuthBody(sessionID, challenge, peerZID, remoteZID string) map[string]any {
	return map[string]any{"session_id": sessionID, "challenge": challenge, "peer_zid": peerZID, "remote_zid": remoteZID}
}

func randomB64URL(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
	session := &Session{}
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
			sendWS(taskErrorFrame(err))
			return
		}
		if !handleFrame(sendWS, frame, fixture, trusted, session) {
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
	taskStateDir := taskStateDirForAudit(auditPath)
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
		tasks, err := readTaskStates(taskStateDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, renderHumanGateway(entries, tasks))
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
	mux.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		tasks, err := readTaskStates(taskStateDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
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

func taskStateDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-tasks"
}

func readTaskStates(dir string) ([]map[string]any, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	tasks := []map[string]any{}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var task map[string]any
		if err := json.Unmarshal(data, &task); err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	sort.Slice(tasks, func(i, j int) bool {
		return optionalString(tasks[i]["task_id"]) < optionalString(tasks[j]["task_id"])
	})
	return tasks, nil
}

func renderHumanGateway(entries, tasks []map[string]any) string {
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
	b.WriteString(`<h2>Tasks</h2><table><thead><tr><th>Task</th><th>Status</th><th>Worker</th><th>Receipt</th><th>Error</th></tr></thead><tbody>`)
	if len(tasks) == 0 {
		b.WriteString(`<tr><td colspan="5">No tasks</td></tr>`)
	}
	for _, task := range tasks {
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(optionalString(task["task_id"])))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(optionalString(task["status"])))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(optionalString(task["worker"])))
		b.WriteString(`</td><td><code>`)
		b.WriteString(html.EscapeString(shortDigest(optionalString(task["receipt_digest"]))))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(optionalString(task["error"])))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<h2>Receipts</h2><table><thead><tr><th>Task</th><th>Worker</th><th>Artifact</th><th>Events</th><th>Approvals</th><th>Sandbox</th></tr></thead><tbody>`)
	if len(receipts) == 0 {
		b.WriteString(`<tr><td colspan="6">No receipts</td></tr>`)
	}
	for _, record := range receipts {
		worker, _ := record["worker"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		sandbox, _ := receipt["sandbox"].(map[string]any)
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
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprintf("%d signed", mapSliceLen(receipt["approval_grants"]))))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(sandbox["mode"])))
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

func shortDigest(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func mapSliceLen(value any) int {
	items, _ := value.([]any)
	return len(items)
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

func (r *TaskRuntime) Register(taskID string, cancel context.CancelFunc) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running[taskID] = cancel
	if r.cancelled[taskID] {
		cancel()
	}
}

func (r *TaskRuntime) Cancel(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancelled[taskID] = true
	if cancel := r.running[taskID]; cancel != nil {
		cancel()
	}
}

func (r *TaskRuntime) Unregister(taskID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, taskID)
}

func (r *TaskRuntime) WasCancelled(taskID string) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancelled[taskID]
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

func (f Fixture) credentialStatus(credential map[string]any, status string) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"issuer":        f.Authority["zid"],
		"credential_id": credentialID(credential),
		"subject":       credential["subject"],
		"status":        status,
	}, "status_signature")
}

func credentialID(credential map[string]any) string {
	body := map[string]any{
		"issuer":     credential["issuer"],
		"subject":    credential["subject"],
		"capability": credential["capability"],
		"claims":     credential["claims"],
	}
	return "credential:sha256:" + digestHex(body)
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

func (f Fixture) verifyTaskCancel(frame map[string]any) (*Worker, map[string]any, map[string]any, error) {
	requester, ok := frame["requester"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("missing requester")
	}
	if err := verifyAgentDescriptor(requester); err != nil {
		return nil, nil, nil, err
	}
	cancel, ok := frame["cancel"].(map[string]any)
	if !ok {
		return nil, nil, nil, errors.New("missing cancel")
	}
	if cancel["from"] != requester["aid"] {
		return nil, nil, nil, errors.New("cancel sender does not match requester descriptor")
	}
	worker := f.workerByAlias(fmt.Sprint(cancel["to"]))
	if worker == nil {
		return nil, nil, nil, errors.New("cancel target does not match worker alias")
	}
	if fmt.Sprint(cancel["task_id"]) == "" {
		return nil, nil, nil, errors.New("cancel task_id missing")
	}
	requesterKey, _, err := publicKey(requester)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := verifyMapSignature(requesterKey, cancel, "signature"); err != nil {
		return nil, nil, nil, errors.New("cancel signature verification failed")
	}
	return worker, requester, cancel, nil
}

func (f Fixture) executeTask(send sendFunc, origin map[string]any, worker *Worker, task map[string]any, parentCheckpoint, retryOf any) error {
	taskID := fmt.Sprint(task["task_id"])
	ctx, cancelRun := context.WithCancel(context.Background())
	f.Runtime.Register(taskID, cancelRun)
	defer cancelRun()
	defer f.Runtime.Unregister(taskID)
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.accepted", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	approvals := toolApprovalReasons(worker.Profile)
	approvalGrants := []map[string]any{}
	if len(approvals) > 0 {
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.required", "task_id": taskID, "reasons": approvals}); err != nil {
			return err
		}
		grant := f.approvalGrant(taskID, approvals)
		approvalGrants = append(approvalGrants, grant)
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.granted", "task_id": taskID, "by": grant["by"], "reasons": approvals, "grant": grant}); err != nil {
			return err
		}
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.started", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := f.writeTaskState(taskID, "running", worker, map[string]any{}); err != nil {
		return err
	}
	policyScope := taskPolicyScope(worker.Profile, worker.Descriptor, task)
	policyDigest := digestHex(policyScope)
	checkpoint := worker.checkpoint(task, parentCheckpoint, 3+len(approvals)*2, policyDigest)
	if err := f.sendTaskEvent(send, map[string]any{"type": "checkpoint.created", "task_id": taskID, "checkpoint": checkpoint}); err != nil {
		return err
	}

	artifactURI := "artifact://local/" + taskID + "/go-summary.md"
	toolName, artifactText, sandbox, err := runTool(ctx, worker.Profile, task, origin)
	if err != nil {
		if f.Runtime.WasCancelled(taskID) {
			return err
		}
		_ = f.writeTaskState(taskID, "failed", worker, map[string]any{"error": err.Error()})
		return err
	}
	sandboxClaim := worker.Profile.SandboxClaim
	if sandboxClaim != "" && sandbox["mode"] != sandboxClaim {
		return errors.New("sandbox claim mismatch")
	}
	artifactManifest, err := writeArtifact(artifactURI, artifactText)
	if err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI, "manifest": artifactManifest}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	sandboxProof := f.sandboxProof(taskID, worker, sandbox, policyDigest, sandboxClaim)

	receipt := map[string]any{
		"task_id":        taskID,
		"from":           task["from"],
		"origin_zone":    origin["zid"],
		"executing_zone": f.Authority["zid"],
		"to":             worker.Descriptor["aid"],
		"artifact_refs":  []string{artifactURI},
		"artifact_manifests": []map[string]any{
			artifactManifest,
		},
		"tool_output_digest": artifactManifest["sha256"],
		"event_count":        float64(5 + len(approvals)*2),
		"approvals":          approvals,
		"approval_grants":    approvalGrants,
		"checkpoint_refs":    []string{fmt.Sprint(checkpoint["checkpoint_id"])},
		"checkpoints":        []map[string]any{checkpoint},
		"policy_scope":       policyScope,
		"policy_digest":      policyDigest,
		"sandbox":            sandbox,
		"sandbox_proof":      sandboxProof,
		"tool":               toolName,
	}
	if sandboxClaim != "" {
		receipt["sandbox_claim"] = sandboxClaim
	}
	if parentCheckpoint != nil {
		receipt["resumed_from"] = parentCheckpoint
	}
	if retryOf != nil {
		receipt["retry_of"] = retryOf
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
	if err := f.writeTaskState(taskID, "completed", worker, map[string]any{"receipt_digest": digestHex(signedReceipt)}); err != nil {
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

func (f Fixture) cancelTask(send sendFunc, origin map[string]any, worker *Worker, requester, cancel map[string]any) error {
	taskID := fmt.Sprint(cancel["task_id"])
	reason := fmt.Sprint(cancel["reason"])
	f.Runtime.Cancel(taskID)
	if err := f.sendTaskEvent(send, map[string]any{
		"type":    "task.cancelled",
		"task_id": taskID,
		"by":      requester["aid"],
		"worker":  worker.Descriptor["aid"],
		"reason":  reason,
	}); err != nil {
		return err
	}
	policyScope := map[string]any{
		"network":           false,
		"write":             []string{},
		"tools":             []string{},
		"data_domains":      []string{},
		"approval_required": []string{},
		"expires_at":        "",
	}
	policyDigest := digestHex(policyScope)
	sandbox := map[string]any{"mode": "not-started"}
	receipt := map[string]any{
		"task_id":            taskID,
		"from":               requester["aid"],
		"origin_zone":        origin["zid"],
		"executing_zone":     f.Authority["zid"],
		"to":                 worker.Descriptor["aid"],
		"status":             "cancelled",
		"cancel":             cancel,
		"artifact_refs":      []string{},
		"artifact_manifests": []map[string]any{},
		"event_count":        float64(1),
		"approvals":          []string{},
		"approval_grants":    []map[string]any{},
		"checkpoint_refs":    []string{},
		"checkpoints":        []map[string]any{},
		"policy_scope":       policyScope,
		"policy_digest":      policyDigest,
		"sandbox":            sandbox,
		"sandbox_proof":      f.sandboxProof(taskID, worker, sandbox, policyDigest, ""),
		"tool":               "none",
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
	if err := f.writeTaskState(taskID, "cancelled", worker, map[string]any{"receipt_digest": digestHex(signedReceipt)}); err != nil {
		return err
	}
	send(map[string]any{
		"type":         "FED_RECEIPT",
		"zone":         receiptRecord["zone"],
		"worker":       receiptRecord["worker"],
		"zone_binding": receiptRecord["zone_binding"],
		"receipt":      receiptRecord["receipt"],
	})
	send(map[string]any{"type": "FED_CANCEL_CLOSE", "task_id": taskID})
	return nil
}

func (w *Worker) checkpoint(task map[string]any, parent any, eventIndex int, policyDigest string) map[string]any {
	taskID := fmt.Sprint(task["task_id"])
	body := map[string]any{
		"task_id":           taskID,
		"parent_checkpoint": parent,
		"event_index":       float64(eventIndex),
		"state_digest":      digestHex(map[string]any{"task": task, "worker": w.Descriptor["aid"]}),
		"artifact_refs":     []string{},
		"policy_digest":     policyDigest,
		"created_by":        w.Descriptor["aid"],
	}
	body["checkpoint_id"] = "checkpoint:sha256:" + digestHex(body)
	return signBodyWithKey(w.PrivateKey, body, "checkpoint_signature")
}

func (f Fixture) approvalGrant(taskID string, reasons []string) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"task_id":   taskID,
		"authority": f.Authority["zid"],
		"by":        "human://go-gateway/operator",
		"method":    "local.signed",
		"reasons":   reasons,
	}, "approval_signature")
}

func (f Fixture) sandboxProof(taskID string, worker *Worker, sandbox map[string]any, policyDigest, sandboxClaim string) map[string]any {
	body := map[string]any{
		"proof_type":    "local.sandbox.v1",
		"authority":     f.Authority["zid"],
		"task_id":       taskID,
		"worker":        worker.Descriptor["aid"],
		"policy_digest": policyDigest,
		"sandbox":       sandbox,
	}
	if sandboxClaim != "" {
		body["sandbox_claim"] = sandboxClaim
	}
	return signBodyWithKey(f.AuthorityPrivateKey, body, "sandbox_signature")
}

func toolApprovalReasons(profile WorkerProfile) []string {
	required := stringsFromAny(profile.Policy["approval_required"])
	for _, item := range required {
		if item == "tool" && (profile.Tool == "external.stdio" || profile.Tool == "mcp.stdio") {
			return []string{"tool"}
		}
	}
	return []string{}
}

func taskPolicyScope(profile WorkerProfile, worker, task map[string]any) map[string]any {
	scope, _ := task["scope"].(map[string]any)
	policy, _ := worker["policy"].(map[string]any)
	tool := profile.Tool
	if tool == "" {
		tool = "text.echo"
	}
	return map[string]any{
		"network":           scope["network"] == true,
		"write":             stringsFromAny(scope["write"]),
		"tools":             []string{tool},
		"data_domains":      stringsFromAny(scope["data_domains"]),
		"approval_required": stringsFromAny(policy["approval_required"]),
		"expires_at":        optionalString(scope["expires_at"]),
	}
}

func runTool(ctx context.Context, profile WorkerProfile, task, origin map[string]any) (string, string, map[string]any, error) {
	tool := profile.Tool
	if tool == "" {
		tool = "text.echo"
	}
	taskID := fmt.Sprint(task["task_id"])
	intent := fmt.Sprint(task["intent"])
	switch tool {
	case "summarize.mock":
		return tool, "# Go Tool Summary\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nSummary: " + intent + "\n", inProcessSandbox(), nil
	case "translate.mock":
		return tool, "# Go Tool Translation\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nTranslation: " + strings.ToUpper(intent) + "\n", inProcessSandbox(), nil
	case "external.stdio":
		text, sandbox, err := runExternalTool(ctx, profile, task, origin)
		return tool, text, sandbox, err
	case "mcp.stdio":
		text, sandbox, err := runMCPTool(ctx, profile, task, origin)
		return tool, text, sandbox, err
	default:
		return tool, "# Go Tool Output\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nOutput: " + intent + "\n", inProcessSandbox(), nil
	}
}

func inProcessSandbox() map[string]any {
	return map[string]any{"mode": "in-process"}
}

func newToolSandbox(kind string, toolCommand []string) (string, map[string]any, func(), error) {
	dir, err := os.MkdirTemp("", "agnet-"+kind+"-*")
	if err != nil {
		return "", nil, nil, err
	}
	sandbox := map[string]any{
		"mode":            "local-temp-dir",
		"isolation_level": "local-process",
		"kind":            kind,
		"cwd":             dir,
		"env":             []string{"PATH=/usr/bin:/bin"},
		"network":         "not_granted",
		"cleanup":         "remove-all",
	}
	if len(toolCommand) > 0 {
		sandbox["tool_command_digest"] = digestHex(toolCommand)
	}
	return dir, sandbox, func() { _ = os.RemoveAll(dir) }, nil
}

func sandboxEnv() []string {
	return []string{"PATH=/usr/bin:/bin"}
}

func runExternalTool(parent context.Context, profile WorkerProfile, task, origin map[string]any) (string, map[string]any, error) {
	if len(profile.ToolCommand) == 0 {
		return "", nil, errors.New("external.stdio tool_command missing")
	}
	dir, sandbox, cleanup, err := newToolSandbox("external", profile.ToolCommand)
	if err != nil {
		return "", nil, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = sandboxEnv()
	input := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
		"tool":    profile.Tool,
	}
	data, err := json.Marshal(input)
	if err != nil {
		return "", nil, err
	}
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if ctx.Err() == context.Canceled {
		return "", nil, errors.New("external tool cancelled")
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", nil, errors.New("external tool timed out")
	}
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", nil, errors.New("external tool failed: " + message)
	}
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		return "", nil, err
	}
	text, ok := result["text"].(string)
	if !ok || text == "" {
		return "", nil, errors.New("external tool text missing")
	}
	return text, sandbox, nil
}

func runMCPTool(parent context.Context, profile WorkerProfile, task, origin map[string]any) (string, map[string]any, error) {
	if len(profile.ToolCommand) == 0 {
		return "", nil, errors.New("mcp.stdio tool_command missing")
	}
	toolName := profile.ToolName
	if toolName == "" {
		return "", nil, errors.New("mcp.stdio tool_name missing")
	}
	dir, sandbox, cleanup, err := newToolSandbox("mcp", profile.ToolCommand)
	if err != nil {
		return "", nil, err
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, profile.ToolCommand[0], profile.ToolCommand[1:]...)
	cmd.Dir = dir
	cmd.Env = sandboxEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", nil, err
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
		return "", nil, err
	}
	initializeResponse, err := readRPCResponse(scanner, 1)
	if err != nil {
		return "", nil, err
	}
	if result, ok := initializeResponse["result"].(map[string]any); ok {
		sandbox["mcp_session"] = map[string]any{
			"protocol_version": result["protocolVersion"],
			"server_info":      result["serverInfo"],
		}
	}
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized", "params": map[string]any{}}); err != nil {
		return "", nil, err
	}
	if _, err := recordMCPListEvidence(writeRPC, scanner, sandbox, 2, "resources/list", "resources", "mcp_resources"); err != nil {
		return "", nil, err
	}
	if _, err := recordMCPListEvidence(writeRPC, scanner, sandbox, 3, "prompts/list", "prompts", "mcp_prompts"); err != nil {
		return "", nil, err
	}
	tools, err := recordMCPListEvidence(writeRPC, scanner, sandbox, 4, "tools/list", "tools", "mcp_tools")
	if err != nil {
		return "", nil, err
	}
	schema, err := recordMCPSelectedToolEvidence(sandbox, tools, toolName)
	if err != nil {
		return "", nil, err
	}
	args := map[string]any{
		"task_id": task["task_id"],
		"intent":  task["intent"],
		"to":      task["to"],
		"origin":  origin["zid"],
	}
	sandbox["mcp_tool_arguments_digest"] = digestHex(args)
	if err := validateMCPRequiredArguments(schema, args); err != nil {
		return "", nil, err
	}
	if err := writeRPC(map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params":  map[string]any{"name": toolName, "arguments": args},
	}); err != nil {
		return "", nil, err
	}
	response, err := readRPCResponse(scanner, 5)
	if err != nil {
		return "", nil, err
	}
	_ = stdin.Close()
	if ctx.Err() == context.Canceled {
		return "", nil, errors.New("mcp tool cancelled")
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", nil, errors.New("mcp tool failed: " + message)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", nil, errors.New("mcp tool timed out")
	}
	text, err := mcpText(response)
	return text, sandbox, err
}

func recordMCPListEvidence(writeRPC func(map[string]any) error, scanner *bufio.Scanner, sandbox map[string]any, id float64, method, field, prefix string) ([]any, error) {
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": map[string]any{}}); err != nil {
		return nil, err
	}
	response, err := readRPCResponse(scanner, id)
	if err != nil {
		return nil, err
	}
	result, _ := response["result"].(map[string]any)
	items, _ := result[field].([]any)
	sandbox[prefix+"_count"] = float64(len(items))
	sandbox[prefix+"_digest"] = digestHex(items)
	return items, nil
}

func recordMCPSelectedToolEvidence(sandbox map[string]any, tools []any, toolName string) (any, error) {
	for _, item := range tools {
		tool, _ := item.(map[string]any)
		if tool["name"] == toolName {
			sandbox["mcp_selected_tool"] = toolName
			sandbox["mcp_selected_tool_digest"] = digestHex(tool)
			var selectedSchema any
			if schema, ok := tool["inputSchema"]; ok {
				selectedSchema = schema
				sandbox["mcp_selected_tool_schema_digest"] = digestHex(schema)
			}
			return selectedSchema, nil
		}
	}
	return nil, errors.New("mcp selected tool missing from tools/list")
}

func validateMCPRequiredArguments(schema any, args map[string]any) error {
	body, _ := schema.(map[string]any)
	required, _ := body["required"].([]any)
	for _, item := range required {
		name, ok := item.(string)
		if !ok {
			continue
		}
		// ponytail: required-only gate; full JSON Schema validation belongs in a later policy slice.
		if _, ok := args[name]; !ok {
			return errors.New("mcp tool arguments missing required field: " + name)
		}
	}
	return nil
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

func (f Fixture) writeTaskState(taskID, status string, worker *Worker, extra map[string]any) error {
	if f.TaskStateDir == "" {
		return nil
	}
	body := map[string]any{
		"task_id": taskID,
		"status":  status,
		"worker":  worker.Descriptor["aid"],
	}
	for key, value := range extra {
		body[key] = value
	}
	if err := os.MkdirAll(f.TaskStateDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	// ponytail: one JSON file per task; replace with an indexed store when scheduling needs queries.
	return os.WriteFile(filepath.Join(f.TaskStateDir, url.PathEscape(taskID)+".json"), append(data, '\n'), 0o644)
}

func writeArtifact(uri, text string) (map[string]any, error) {
	const prefix = "artifact://local/"
	if !strings.HasPrefix(uri, prefix) {
		return nil, errors.New("unsupported artifact uri: " + uri)
	}
	path := filepath.Join("artifacts", strings.TrimPrefix(uri, prefix))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	data := []byte(text)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	body := map[string]any{
		"uri":        uri,
		"sha256":     digestBytesHex(data),
		"size":       float64(len(data)),
		"media_type": "text/markdown; charset=utf-8",
	}
	body["manifest_hash"] = digestHex(body)
	return body, nil
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
	zoneKey, _, err := publicKey(zone)
	if err != nil {
		return err
	}
	if err := verifyApprovalGrants(zoneKey, receipt); err != nil {
		return err
	}
	if err := verifyCheckpoints(workerKey, receipt); err != nil {
		return err
	}
	if err := verifyArtifactManifests(receipt); err != nil {
		return err
	}
	if err := verifyPolicyScope(receipt); err != nil {
		return err
	}
	if err := verifySandboxProof(zoneKey, receipt); err != nil {
		return err
	}
	return nil
}

func verifyApprovalGrants(zoneKey ed25519.PublicKey, receipt map[string]any) error {
	approvals := stringsFromAny(receipt["approvals"])
	grants := mapsFromAny(receipt["approval_grants"])
	if len(approvals) != len(grants) {
		return errors.New("receipt approval grant count mismatch")
	}
	for _, grant := range grants {
		if grant["task_id"] != receipt["task_id"] {
			return errors.New("approval grant task mismatch")
		}
		if err := verifyMapSignature(zoneKey, grant, "approval_signature"); err != nil {
			return errors.New("approval signature verification failed")
		}
	}
	return nil
}

func verifyCheckpoints(workerKey ed25519.PublicKey, receipt map[string]any) error {
	refs := stringsFromAny(receipt["checkpoint_refs"])
	checkpoints := mapsFromAny(receipt["checkpoints"])
	if len(refs) != len(checkpoints) {
		return errors.New("receipt checkpoint ref count mismatch")
	}
	parent := any(nil)
	if resumedFrom, ok := receipt["resumed_from"]; ok {
		parent = resumedFrom
	}
	for index, checkpoint := range checkpoints {
		if checkpoint["task_id"] != receipt["task_id"] {
			return errors.New("checkpoint task mismatch")
		}
		if checkpoint["checkpoint_id"] != refs[index] {
			return errors.New("checkpoint ref mismatch")
		}
		if checkpoint["parent_checkpoint"] != parent {
			return errors.New("checkpoint parent mismatch")
		}
		if err := verifyMapSignature(workerKey, checkpoint, "checkpoint_signature"); err != nil {
			return errors.New("checkpoint signature verification failed")
		}
		parent = checkpoint["checkpoint_id"]
	}
	return nil
}

func verifyArtifactManifests(receipt map[string]any) error {
	refs := stringsFromAny(receipt["artifact_refs"])
	manifests := mapsFromAny(receipt["artifact_manifests"])
	if len(refs) != len(manifests) {
		return errors.New("receipt artifact manifest count mismatch")
	}
	for index, manifest := range manifests {
		if manifest["uri"] != refs[index] {
			return errors.New("artifact manifest uri mismatch")
		}
		for _, field := range []string{"sha256", "media_type", "manifest_hash"} {
			if fmt.Sprint(manifest[field]) == "" {
				return errors.New("artifact manifest " + field + " missing")
			}
		}
		if _, ok := manifest["size"].(float64); !ok {
			return errors.New("artifact manifest size missing")
		}
		body := map[string]any{}
		for k, v := range manifest {
			if k != "manifest_hash" {
				body[k] = v
			}
		}
		if manifest["manifest_hash"] != digestHex(body) {
			return errors.New("artifact manifest hash mismatch")
		}
	}
	if digest, ok := receipt["tool_output_digest"]; ok && len(manifests) > 0 && digest != manifests[0]["sha256"] {
		return errors.New("tool output digest mismatch")
	}
	return nil
}

func verifyPolicyScope(receipt map[string]any) error {
	scope, ok := receipt["policy_scope"].(map[string]any)
	if !ok {
		return errors.New("receipt policy scope missing")
	}
	for _, field := range []string{"network", "write", "tools", "data_domains", "approval_required", "expires_at"} {
		if _, ok := scope[field]; !ok {
			return errors.New("policy scope " + field + " missing")
		}
	}
	if fmt.Sprint(receipt["policy_digest"]) == "" {
		return errors.New("receipt policy digest missing")
	}
	if receipt["policy_digest"] != digestHex(scope) {
		return errors.New("policy digest mismatch")
	}
	return nil
}

func verifySandboxProof(zoneKey ed25519.PublicKey, receipt map[string]any) error {
	proof, ok := receipt["sandbox_proof"].(map[string]any)
	if !ok {
		return errors.New("receipt sandbox proof missing")
	}
	sandbox, ok := receipt["sandbox"].(map[string]any)
	if !ok {
		return errors.New("receipt sandbox missing")
	}
	if proof["proof_type"] != "local.sandbox.v1" {
		return errors.New("sandbox proof type mismatch")
	}
	if proof["authority"] != receipt["executing_zone"] {
		return errors.New("sandbox proof authority mismatch")
	}
	if proof["task_id"] != receipt["task_id"] {
		return errors.New("sandbox proof task mismatch")
	}
	if proof["worker"] != receipt["to"] {
		return errors.New("sandbox proof worker mismatch")
	}
	if proof["policy_digest"] != receipt["policy_digest"] {
		return errors.New("sandbox proof policy mismatch")
	}
	if digestHex(proof["sandbox"]) != digestHex(sandbox) {
		return errors.New("sandbox proof evidence mismatch")
	}
	if claim, ok := receipt["sandbox_claim"]; ok && proof["sandbox_claim"] != claim {
		return errors.New("sandbox proof claim mismatch")
	}
	if err := verifyMapSignature(zoneKey, proof, "sandbox_signature"); err != nil {
		return errors.New("sandbox proof signature verification failed")
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
		return policyError{code: "policy.network_denied", message: "policy denied network access"}
	}
	for _, target := range stringsFromAny(scope["write"]) {
		if !hasPrefix(target, stringsFromAny(policy["write_prefixes"])) {
			return policyError{code: "policy.write_denied", message: "policy denied write scope: " + target}
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

func optionalString(value any) string {
	text, _ := value.(string)
	return text
}

func mapsFromAny(value any) []map[string]any {
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
	data, _ := json.Marshal(value)
	return digestBytesHex(data)
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
