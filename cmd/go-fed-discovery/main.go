package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
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
	"strconv"
	"strings"
	"sync"
	"time"
)

type Fixture struct {
	Authority           map[string]any      `json:"authority"`
	WorkerProfile       WorkerProfile       `json:"worker_profile"`
	WorkerProfiles      []WorkerProfile     `json:"worker_profiles"`
	Workers             []Worker            `json:"-"`
	Credential          map[string]any      `json:"credential"`
	AuthorityPrivateKey ed25519.PrivateKey  `json:"-"`
	Audit               *AuditLog           `json:"-"`
	TaskStateDir        string              `json:"-"`
	QueueDir            string              `json:"-"`
	ApprovalDir         string              `json:"-"`
	ArtifactStoreDir    string              `json:"-"`
	LiveTranscriptDir   string              `json:"-"`
	Runtime             *TaskRuntime        `json:"-"`
	QueueActorPolicy    map[string][]string `json:"-"`
	ApprovalActorPolicy map[string][]string `json:"-"`
	ApprovalSessions    map[string]string   `json:"-"`
}

const requesterRegistryPath = "state/go-fed-discovery-requester-registry.json"
const requesterRebindingHistoryPath = "state/go-fed-discovery-requester-rebindings.json"

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
	Zones       []map[string]any `json:"zones"`
	Revocations []map[string]any `json:"revocations,omitempty"`
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

var approvalStateMu sync.Mutex

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
	humanPort := flag.String("human-port", "", "optional Human Gateway HTTP port")
	humanToken := flag.String("human-token", "", "optional Human Gateway bearer token for write actions")
	humanActorPolicyPath := flag.String("human-actor-policy", "", "optional Human Gateway actor policy JSON file")
	artifactStoreDir := flag.String("artifact-store", "", "optional filesystem artifact mirror directory")
	fixturePath := flag.String("fixture", "test-vectors/asp-v1.5-capability-credential.json", "signed descriptor fixture")
	trustPath := flag.String("trusted", "state/go-fed-trusted-zones.json", "trusted origin zones")
	authorityKeyPath := flag.String("authority-key", "state/keys/go-fed-authority.seed", "authority seed key file")
	workerKeyPath := flag.String("worker-key", "state/keys/go-fed-worker.seed", "worker seed key file")
	auditPath := flag.String("audit", "state/go-fed-audit.log", "audit JSONL file")
	verifyAudit := flag.Bool("verify-audit", false, "verify audit JSONL file and exit")
	verifyReceiptPath := flag.String("verify-receipt", "", "verify one receipt record JSON file and exit")
	artifactStoreGCPlan := flag.Bool("artifact-store-gc-plan", false, "print filesystem artifact mirror GC plan and exit")
	artifactStoreGCApply := flag.Bool("artifact-store-gc-apply", false, "delete orphaned filesystem artifact mirror objects and exit")
	flag.Parse()

	if *verifyAudit {
		if err := verifyAuditFile(*auditPath, *artifactStoreDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(`{"go_audit_verify":"ok"}`)
		return
	}
	if *verifyReceiptPath != "" {
		result, err := verifyReceiptFile(*verifyReceiptPath, *artifactStoreDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *artifactStoreGCPlan {
		plan, err := planArtifactStoreGC(*auditPath, *artifactStoreDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *artifactStoreGCApply {
		result, err := applyArtifactStoreGC(*auditPath, *artifactStoreDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if err := serve(*port, *wsPort, *humanPort, *humanToken, *humanActorPolicyPath, *artifactStoreDir, *fixturePath, *trustPath, *authorityKeyPath, *workerKeyPath, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(port, wsPort, humanPort, humanToken, humanActorPolicyPath, artifactStoreDir, fixturePath, trustPath, authorityKeyPath, workerKeyPath, auditPath string) error {
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
	actorPolicy, approvalPolicy, approvalSessions, err := loadHumanActorPolicy(humanActorPolicyPath)
	if err != nil {
		return err
	}
	fixture.QueueActorPolicy = actorPolicy
	fixture.ApprovalActorPolicy = approvalPolicy
	fixture.ApprovalSessions = approvalSessions
	audit, err := openAuditLog(auditPath)
	if err != nil {
		return err
	}
	fixture.Audit = audit
	fixture.TaskStateDir = strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-tasks"
	fixture.QueueDir = queueDirForAudit(auditPath)
	fixture.ApprovalDir = approvalDirForAudit(auditPath)
	fixture.ArtifactStoreDir = artifactStoreDir
	fixture.LiveTranscriptDir = liveTranscriptDirForAudit(auditPath)
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
		go serveHumanGateway(humanListener, auditPath, fixture, humanToken)
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
		if err := fixture.executeTask(send, origin, worker, task, nil, "", nil, true, nil); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_ENQUEUE":
		taskID, workerID, err := fixture.enqueueQueueItem(origin, frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{"type": "FED_QUEUE_ACCEPTED", "task_id": taskID, "worker": workerID})
		send(map[string]any{"type": "FED_QUEUE_CLOSE", "task_id": taskID})
	case "FED_QUEUE_RESUME":
		taskID, workerID, err := fixture.enqueueResumeQueueItem(origin, frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{"type": "FED_QUEUE_RESUME_ACCEPTED", "task_id": taskID, "worker": workerID, "checkpoint_id": frame["checkpoint_id"]})
		send(map[string]any{"type": "FED_QUEUE_RESUME_CLOSE", "task_id": taskID})
	case "FED_QUEUE_RETRY":
		taskID, err := fixture.retryQueueItem(origin, frame, frameSeconds(frame, "retry_after_seconds", 60))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{"type": "FED_QUEUE_RETRY_ACCEPTED", "task_id": taskID, "retry_of": frame["retry_of"]})
		send(map[string]any{"type": "FED_QUEUE_RETRY_CLOSE", "task_id": taskID})
	case "FED_QUEUE_CLAIM":
		taskID := fmt.Sprint(frame["task_id"])
		owner := fmt.Sprint(frame["owner"])
		if taskID == "" || taskID == "<nil>" || owner == "" || owner == "<nil>" {
			send(taskErrorFrame(errors.New("queue claim task_id and owner required")))
			return false
		}
		leaseID, err := fixture.claimQueueItem(taskID, owner, frameSeconds(frame, "lease_seconds", 60))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{"type": "FED_QUEUE_CLAIMED", "task_id": taskID, "lease_id": leaseID, "owner": owner})
		send(map[string]any{"type": "FED_QUEUE_CLAIM_CLOSE", "task_id": taskID})
	case "FED_QUEUE_RECLAIM":
		taskID := fmt.Sprint(frame["task_id"])
		owner := fmt.Sprint(frame["owner"])
		if taskID == "" || taskID == "<nil>" || owner == "" || owner == "<nil>" {
			send(taskErrorFrame(errors.New("queue reclaim task_id and owner required")))
			return false
		}
		leaseID, err := fixture.reclaimQueueItem(taskID, owner, frameSeconds(frame, "lease_seconds", 60))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(map[string]any{"type": "FED_QUEUE_RECLAIMED", "task_id": taskID, "lease_id": leaseID, "owner": owner})
		send(map[string]any{"type": "FED_QUEUE_RECLAIM_CLOSE", "task_id": taskID})
	case "FED_QUEUE_DRAIN":
		taskID := fmt.Sprint(frame["task_id"])
		if taskID == "" || taskID == "<nil>" {
			send(taskErrorFrame(errors.New("queue drain task_id missing")))
			return false
		}
		if err := fixture.drainQueueItem(send, taskID, fmt.Sprint(frame["lease_id"])); err != nil {
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
		parentCheckpoint, err := fixture.checkpointByID(checkpointID)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, checkpointID, optionalString(parentCheckpoint["state_digest"]), nil, true, nil); err != nil {
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
		if err := fixture.executeTask(send, origin, worker, task, nil, "", retryOf, true, nil); err != nil {
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
			record["audit_hash"] = entry["hash"]
			return record, nil
		}
	}
	return nil, errors.New("audit proof not found: " + taskID)
}

func (f Fixture) requireCheckpoint(checkpointID string) error {
	_, err := f.checkpointByID(checkpointID)
	return err
}

func (f Fixture) checkpointByID(checkpointID string) (map[string]any, error) {
	if f.Audit == nil {
		return nil, errors.New("audit log unavailable")
	}
	entries, err := readAuditEntries(f.Audit.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("resume checkpoint not found: " + checkpointID)
	}
	if err != nil {
		return nil, err
	}
	// ponytail: linear scan keeps resume evidence honest; add an index when checkpoint lookup has real volume.
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		event, _ := record["event"].(map[string]any)
		checkpoint, _ := event["checkpoint"].(map[string]any)
		if checkpoint["checkpoint_id"] == checkpointID {
			return checkpoint, nil
		}
		receipt, _ := record["receipt"].(map[string]any)
		for _, checkpoint := range mapsFromAny(receipt["checkpoints"]) {
			if checkpoint["checkpoint_id"] == checkpointID {
				return checkpoint, nil
			}
		}
	}
	return nil, errors.New("resume checkpoint not found: " + checkpointID)
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

func serveHumanGateway(listener net.Listener, auditPath string, fixture Fixture, humanToken string) {
	taskStateDir := taskStateDirForAudit(auditPath)
	queueDir := queueDirForAudit(auditPath)
	approvalDir := approvalDirForAudit(auditPath)
	mux := http.NewServeMux()
	requireWriteToken := func(w http.ResponseWriter, r *http.Request) bool {
		if humanToken == "" {
			return true
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			http.Error(w, "human gateway token required", http.StatusUnauthorized)
			return false
		}
		got := strings.TrimPrefix(header, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(humanToken)) != 1 {
			http.Error(w, "human gateway token required", http.StatusUnauthorized)
			return false
		}
		return true
	}
	runQueueAction := func(action map[string]any) (map[string]any, int, error) {
		if err := fixture.requireQueueActionGrant(action); err != nil {
			if auditErr := fixture.recordQueueAction(action, nil, err); auditErr != nil {
				return nil, http.StatusInternalServerError, auditErr
			}
			return nil, http.StatusBadRequest, err
		}
		result, err := fixture.applyQueueAction(action)
		if err != nil {
			if auditErr := fixture.recordQueueAction(action, nil, err); auditErr != nil {
				return nil, http.StatusInternalServerError, auditErr
			}
			return nil, http.StatusBadRequest, err
		}
		if err := fixture.recordQueueAction(action, result, nil); err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return result, http.StatusOK, nil
	}
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
		queue, err := readTaskStates(queueDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		approvals, err := readTaskStates(approvalDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		rebindings, err := readRequesterRebindingHistory()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		requesterRegistry, err := readRequesterRegistry()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, renderHumanGateway(entries, tasks, queue, approvals, rebindings, requesterRegistryAgents(requesterRegistry)))
	})
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) {
		if taskID := r.URL.Query().Get("task_id"); taskID != "" {
			record, err := fixture.auditProof(taskID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"zone":         record["zone"],
				"worker":       record["worker"],
				"zone_binding": record["zone_binding"],
				"receipt":      record["receipt"],
				"audit_hash":   record["audit_hash"],
				"task_id":      taskID,
			})
			return
		}
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
	mux.HandleFunc("/api/queue", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		queue, err := readTaskStates(queueDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"queue": queue})
	})
	mux.HandleFunc("/api/security", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"listen_host":          "127.0.0.1",
			"write_token_required": humanToken != "",
			"public_transport":     false,
		})
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor := fixture.approvalSessionActor(r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authenticated":        actor != "",
			"approval_actor":       actor,
			"approval_actions":     fixture.approvalActionsFor(actor),
			"write_token_required": humanToken != "",
		})
	})
	mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		approvals, err := readTaskStates(approvalDir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"approvals": approvals})
	})
	mux.HandleFunc("/api/approvals/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var action map[string]any
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		actionName := optionalString(action["action"])
		if actionName != "approve" && actionName != "deny" {
			http.Error(w, "unsupported approval action", http.StatusBadRequest)
			return
		}
		taskID := optionalString(action["task_id"])
		actor := optionalString(action["actor"])
		sessionActor := fixture.approvalSessionActor(r)
		if actor != "" && sessionActor != "" && actor != sessionActor {
			http.Error(w, "approval actor session mismatch", http.StatusBadRequest)
			return
		}
		if actor == "" {
			actor = sessionActor
		}
		if taskID == "" || actor == "" || !strings.HasPrefix(actor, "human://") {
			http.Error(w, "approval task_id and human actor required", http.StatusBadRequest)
			return
		}
		if !fixture.approvalActorAllowed(actor, actionName) {
			http.Error(w, "approval actor policy denied", http.StatusBadRequest)
			return
		}
		approval, err := fixture.applyApprovalAction(taskID, actor, actionName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "approval": approval})
	})
	mux.HandleFunc("/api/requester/registry", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		registry, err := readRequesterRegistry()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(registry)
	})
	mux.HandleFunc("/api/queue/actions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var action map[string]any
		if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, status, err := runQueueAction(action)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/api/queue/drafts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var draft map[string]any
		if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if requester, ok := draft["requester"].(map[string]any); ok {
			signedTask, ok := draft["task"].(map[string]any)
			if !ok {
				http.Error(w, "external draft task is required", http.StatusBadRequest)
				return
			}
			taskID := optionalString(signedTask["task_id"])
			if taskID == "" {
				http.Error(w, "external draft task_id is required", http.StatusBadRequest)
				return
			}
			action := map[string]any{
				"action":       "enqueue",
				"origin_zone":  fixture.Authority,
				"requester":    requester,
				"task":         signedTask,
				"actor":        "human://local",
				"action_grant": fixture.queueActionGrant("enqueue", taskID, signedTask),
			}
			result, status, err := runQueueAction(action)
			if err != nil {
				http.Error(w, err.Error(), status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "requester": requester, "task": signedTask, "enqueue": result})
			return
		}
		taskID := optionalString(draft["task_id"])
		to := optionalString(draft["to"])
		intent := optionalString(draft["intent"])
		if taskID == "" || to == "" || intent == "" {
			http.Error(w, "draft task_id, to, and intent are required", http.StatusBadRequest)
			return
		}
		requester, err := fixture.humanGatewayRequester()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		task := map[string]any{
			"task_id": taskID,
			"from":    requester["aid"],
			"to":      to,
			"intent":  intent,
			"scope":   draft["scope"],
			"budget":  draft["budget"],
		}
		signedTask := signBody(fixture.AuthorityPrivateKey, task)
		action := map[string]any{
			"action":       "enqueue",
			"origin_zone":  fixture.Authority,
			"requester":    requester,
			"task":         signedTask,
			"actor":        "human://local",
			"action_grant": fixture.queueActionGrant("enqueue", taskID, signedTask),
		}
		result, status, err := runQueueAction(action)
		if err != nil {
			http.Error(w, err.Error(), status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "requester": requester, "task": signedTask, "enqueue": result})
	})
	mux.HandleFunc("/api/requester/rebindings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			rebindings, err := readRequesterRebindingHistory()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"rebindings": rebindings})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireWriteToken(w, r) {
			return
		}
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		previous, ok := request["previous_descriptor"].(map[string]any)
		if !ok {
			http.Error(w, "previous_descriptor is required", http.StatusBadRequest)
			return
		}
		next, ok := request["next_descriptor"].(map[string]any)
		if !ok {
			http.Error(w, "next_descriptor is required", http.StatusBadRequest)
			return
		}
		rotationProof, ok := request["rotation_proof"].(map[string]any)
		if !ok {
			http.Error(w, "rotation_proof is required", http.StatusBadRequest)
			return
		}
		proof, err := fixture.requesterAliasRebindingProof(previous, next, rotationProof)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := fixture.writeRequesterRegistry(next); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := fixture.appendRequesterRebindingHistory(proof); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "authority_descriptor": fixture.Authority, "alias_rebinding_proof": proof})
	})
	mux.HandleFunc("/api/artifacts/manifest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uri := r.URL.Query().Get("uri")
		if uri == "" {
			http.Error(w, "artifact uri is required", http.StatusBadRequest)
			return
		}
		if taskID := r.URL.Query().Get("task_id"); taskID != "" {
			record, err := fixture.auditProof(taskID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			receipt, _ := record["receipt"].(map[string]any)
			manifest, err := receiptArtifactManifest(receipt, uri)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
			w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
			w.Header().Set("X-Agent-Space-Artifact-SHA256", fmt.Sprint(manifest["sha256"]))
			w.Header().Set("X-Agent-Space-Artifact-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
			if r.Method == http.MethodHead {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"task_id": taskID, "uri": uri, "audit_hash": record["audit_hash"], "receipt_digest": digestHex(receipt), "manifest": manifest})
			return
		}
		if r.Method == http.MethodHead {
			http.Error(w, "task_id is required for artifact manifest HEAD", http.StatusBadRequest)
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path + ".manifest.json")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/artifacts/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		uri := r.URL.Query().Get("uri")
		if taskID == "" || uri == "" {
			http.Error(w, "task_id and artifact uri are required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "task_id": taskID, "uri": uri, "audit_hash": record["audit_hash"], "receipt_digest": digestHex(receipt), "manifest": manifest})
	})
	mux.HandleFunc("/api/artifacts/read", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		uri := r.URL.Query().Get("uri")
		if taskID == "" || uri == "" {
			http.Error(w, "task_id and artifact uri are required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", fmt.Sprint(manifest["media_type"]))
		w.Header().Set("Content-Length", fmt.Sprint(manifest["size"]))
		w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
		w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
		w.Header().Set("X-Agent-Space-Artifact-SHA256", fmt.Sprint(manifest["sha256"]))
		w.Header().Set("X-Agent-Space-Artifact-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
		if r.Method == http.MethodHead {
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/transcripts/stream", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		if taskID == "" {
			http.Error(w, "task_id is required", http.StatusBadRequest)
			return
		}
		record, err := fixture.auditProof(taskID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		receipt, _ := record["receipt"].(map[string]any)
		sandbox, _ := receipt["sandbox"].(map[string]any)
		uri := optionalString(sandbox["tool_transcript_ref"])
		if uri == "" {
			http.Error(w, "task transcript not found", http.StatusNotFound)
			return
		}
		manifest, err := receiptArtifactManifest(receipt, uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if err := verifyArtifactManifests(receipt, fixture.ArtifactStoreDir); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		path, err := localArtifactPath(uri)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !json.Valid(data) {
			http.Error(w, "task transcript is not json", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("X-Agent-Space-Audit-Hash", fmt.Sprint(record["audit_hash"]))
		w.Header().Set("X-Agent-Space-Receipt-Digest", digestHex(receipt))
		w.Header().Set("X-Agent-Space-Transcript-SHA256", fmt.Sprint(manifest["sha256"]))
		w.Header().Set("X-Agent-Space-Transcript-Manifest-Hash", fmt.Sprint(manifest["manifest_hash"]))
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "transcript.chunk", "task_id": taskID, "uri": uri, "transcript": json.RawMessage(data)})
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	})
	mux.HandleFunc("/api/transcripts/live", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		taskID := r.URL.Query().Get("task_id")
		if taskID == "" {
			http.Error(w, "task_id is required", http.StatusBadRequest)
			return
		}
		data, err := os.ReadFile(filepath.Join(fixture.LiveTranscriptDir, url.PathEscape(taskID)+".ndjson"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.NotFound(w, r)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		_, _ = w.Write(data)
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

func queueDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-queue"
}

func approvalDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-approvals"
}

func liveTranscriptDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-live-transcripts"
}

func queueGrantDirForAudit(auditPath string) string {
	return strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + "-queue-grants"
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

func renderHumanGateway(entries, tasks, queue, approvals, rebindings, requesterAgents []map[string]any) string {
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
form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;background:white;border:1px solid #d9dee7;padding:12px}label{display:grid;gap:4px;font-size:12px;color:#4c5563}input,textarea{font:inherit;padding:7px;border:1px solid #c8ced8}button{font:inherit;padding:7px 10px;border:1px solid #aab3c1;background:#eef1f5}.toolrow{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}pre{white-space:pre-wrap;background:white;border:1px solid #d9dee7;padding:10px;font-size:12px}
a{color:#0b5cad;text-decoration:none}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
</style></head><body><main>`)
	b.WriteString(`<header><div><h1>Agent Space Human Gateway</h1><div class="metric">read-only / local proof</div></div><div class="metric">audit entries: `)
	b.WriteString(fmt.Sprint(len(entries)))
	b.WriteString(` · events: `)
	b.WriteString(fmt.Sprint(events))
	b.WriteString(` · receipts: `)
	b.WriteString(fmt.Sprint(len(receipts)))
	b.WriteString(`</div></header>`)
	b.WriteString(sessionPanel())
	b.WriteString(browserRequesterPanel())
	b.WriteString(`<h2>Tasks</h2><table><thead><tr><th>Task</th><th>Status</th><th>Worker</th><th>Receipt</th><th>Error</th></tr></thead><tbody>`)
	if len(tasks) == 0 {
		b.WriteString(`<tr><td colspan="5">No tasks</td></tr>`)
	}
	for _, task := range tasks {
		taskID := optionalString(task["task_id"])
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(taskID))
		b.WriteString(`</code>`)
		if optionalString(task["status"]) == "running" {
			b.WriteString(`<br><button type="button" onclick="loadLiveTranscript(`)
			b.WriteString(html.EscapeString(strconv.Quote(taskID)))
			b.WriteString(`)">live transcript</button>`)
		}
		b.WriteString(`</td><td>`)
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
	b.WriteString(`<h2>Queue</h2><table><thead><tr><th>Task</th><th>Status</th><th>Worker</th><th>Lease</th><th>Retry</th></tr></thead><tbody>`)
	if len(queue) == 0 {
		b.WriteString(`<tr><td colspan="5">No queue items</td></tr>`)
	}
	for _, item := range queue {
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(optionalString(item["task_id"])))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(optionalString(item["status"])))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(optionalString(item["worker"])))
		b.WriteString(`</td><td><code>`)
		b.WriteString(html.EscapeString(shortDigest(optionalString(item["lease_id"]))))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(optionalString(item["retry_after_at"])))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<h2>Approvals</h2><table><thead><tr><th>Task</th><th>Status</th><th>Reasons</th><th>By</th></tr></thead><tbody>`)
	if len(approvals) == 0 {
		b.WriteString(`<tr><td colspan="4">No approvals</td></tr>`)
	}
	for _, approval := range approvals {
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(optionalString(approval["task_id"])))
		b.WriteString(`</code></td><td>`)
		b.WriteString(html.EscapeString(optionalString(approval["status"])))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(strings.Join(stringsFromAny(approval["reasons"]), ", ")))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(optionalString(approval["by"])))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<h2>Requester Registry</h2><table><thead><tr><th>Alias</th><th>AID</th><th>Zone</th></tr></thead><tbody>`)
	if len(requesterAgents) == 0 {
		b.WriteString(`<tr><td colspan="3">No requester registry entries</td></tr>`)
	}
	for _, entry := range requesterAgents {
		descriptor, _ := entry["descriptor"].(map[string]any)
		binding, _ := entry["zone_binding"].(map[string]any)
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(optionalString(descriptor["alias"])))
		b.WriteString(`</code></td><td><code>`)
		b.WriteString(html.EscapeString(optionalString(descriptor["aid"])))
		b.WriteString(`</code></td><td><code>`)
		b.WriteString(html.EscapeString(optionalString(binding["zone"])))
		b.WriteString(`</code></td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<h2>Requester Rebindings</h2><table><thead><tr><th>Alias</th><th>Previous</th><th>Next</th><th>Proof</th></tr></thead><tbody>`)
	if len(rebindings) == 0 {
		b.WriteString(`<tr><td colspan="4">No requester rebindings</td></tr>`)
	}
	for _, rebinding := range rebindings {
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(optionalString(rebinding["alias"])))
		b.WriteString(`</code></td><td><code>`)
		b.WriteString(html.EscapeString(optionalString(rebinding["previous_aid"])))
		b.WriteString(`</code></td><td><code>`)
		b.WriteString(html.EscapeString(optionalString(rebinding["next_aid"])))
		b.WriteString(`</code></td><td><code>`)
		b.WriteString(html.EscapeString(shortDigest(optionalString(rebinding["proof_digest"]))))
		b.WriteString(`</code></td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	b.WriteString(`<h2>Receipts</h2><table><thead><tr><th>Task</th><th>Worker</th><th>Artifacts</th><th>Events</th><th>Approvals</th><th>Sandbox</th></tr></thead><tbody>`)
	if len(receipts) == 0 {
		b.WriteString(`<tr><td colspan="6">No receipts</td></tr>`)
	}
	for _, record := range receipts {
		worker, _ := record["worker"].(map[string]any)
		receipt, _ := record["receipt"].(map[string]any)
		sandbox, _ := receipt["sandbox"].(map[string]any)
		taskID := fmt.Sprint(receipt["task_id"])
		b.WriteString(`<tr><td><code>`)
		b.WriteString(html.EscapeString(taskID))
		b.WriteString(`</code> <a href="/api/audit?task_id=`)
		b.WriteString(html.EscapeString(url.QueryEscape(taskID)))
		b.WriteString(`">proof</a></td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(worker["alias"])))
		b.WriteString(`</td><td>`)
		transcriptRef := optionalString(sandbox["tool_transcript_ref"])
		for index, artifact := range stringsFromAny(receipt["artifact_refs"]) {
			if index > 0 {
				b.WriteString(`<br>`)
			}
			b.WriteString(`<a href="/artifacts/`)
			b.WriteString(html.EscapeString(strings.TrimPrefix(artifact, "artifact://local/")))
			b.WriteString(`">`)
			b.WriteString(html.EscapeString(artifact))
			b.WriteString(`</a>`)
			b.WriteString(` <a href="/api/artifacts/manifest?task_id=`)
			b.WriteString(html.EscapeString(url.QueryEscape(taskID)))
			b.WriteString(`&amp;uri=`)
			b.WriteString(html.EscapeString(url.QueryEscape(artifact)))
			b.WriteString(`">manifest</a>`)
			b.WriteString(` <a href="/api/artifacts/verify?task_id=`)
			b.WriteString(html.EscapeString(url.QueryEscape(taskID)))
			b.WriteString(`&amp;uri=`)
			b.WriteString(html.EscapeString(url.QueryEscape(artifact)))
			b.WriteString(`">verify</a>`)
			b.WriteString(` <a href="/api/artifacts/read?task_id=`)
			b.WriteString(html.EscapeString(url.QueryEscape(taskID)))
			b.WriteString(`&amp;uri=`)
			b.WriteString(html.EscapeString(url.QueryEscape(artifact)))
			b.WriteString(`">read</a>`)
		}
		if transcriptRef != "" {
			b.WriteString(`<br><button type="button" onclick="loadTranscript(`)
			b.WriteString(html.EscapeString(strconv.Quote(taskID)))
			b.WriteString(`)">stream transcript</button>`)
		}
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(receipt["event_count"])))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprintf("%d signed", mapSliceLen(receipt["approval_grants"]))))
		b.WriteString(`</td><td>`)
		b.WriteString(html.EscapeString(fmt.Sprint(sandbox["mode"])))
		b.WriteString(`</td></tr>`)
	}
	b.WriteString(`</tbody></table><h2>Transcript</h2><pre id="transcript-viewer">No transcript selected</pre><script>
let liveTranscriptPoller;
async function loadTranscript(taskID) {
  clearInterval(liveTranscriptPoller);
  const viewer = document.getElementById("transcript-viewer");
  const response = await fetch("/api/transcripts/stream?task_id=" + encodeURIComponent(taskID));
  viewer.textContent = response.ok ? await response.text() : await response.text();
}
async function refreshLiveTranscript(taskID) {
  const viewer = document.getElementById("transcript-viewer");
  const response = await fetch("/api/transcripts/live?task_id=" + encodeURIComponent(taskID));
  viewer.textContent = response.ok ? await response.text() : await response.text();
}
async function loadLiveTranscript(taskID) {
  clearInterval(liveTranscriptPoller);
  await refreshLiveTranscript(taskID);
  liveTranscriptPoller = setInterval(() => refreshLiveTranscript(taskID), 1000);
}
</script><h2>Audit</h2><table><thead><tr><th>Index</th><th>Kind</th><th>Hash</th></tr></thead><tbody>`)
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

func sessionPanel() string {
	return `<section id="session"><h2>Session</h2><div class="toolrow"><input id="session-token" type="password" autocomplete="off" placeholder="Bearer token"><button id="session-refresh" type="button">Refresh</button></div><pre id="session-status">Checking session...</pre></section><script>
(() => {
  const token = document.getElementById("session-token");
  const status = document.getElementById("session-status");
  const refresh = async () => {
    const headers = token.value ? { authorization: "Bearer " + token.value } : {};
    const response = await fetch("/api/session", { headers });
    const session = await response.json();
    status.textContent = session.authenticated
      ? session.approval_actor + " · " + session.approval_actions.join(", ")
      : "Unauthenticated";
  };
  document.getElementById("session-refresh").onclick = refresh;
  refresh().catch((error) => { status.textContent = error.message; });
})();
</script>`
}

func browserRequesterPanel() string {
	return `<section id="browser-requester"><h2>Browser Requester Key</h2><div class="toolrow"><button id="browser-generate-key" type="button">Generate</button><button id="browser-clear-key" type="button">Clear</button><button id="browser-export-key" type="button">Export Key</button><button id="browser-import-key" type="button">Import Key</button><button id="browser-rotate-key" type="button">Rotate Key</button><button id="browser-rebind-key" type="button">Bind Alias</button></div><textarea id="browser-key-bundle" rows="4" spellcheck="false" aria-label="Browser requester key bundle"></textarea><form id="browser-draft-form"><label>Task<input id="browser-task-id" value="browser_draft_task"></label><label>Target<input id="browser-task-to" value="agent://zone-b/translator"></label><label>Intent<input id="browser-task-intent" value="Draft from a browser-held requester key."></label><label>Token<input id="browser-token" type="password" autocomplete="off"></label><button type="submit">Sign Draft</button></form><pre id="browser-requester-status"></pre></section><script>
(() => {
  const storageKey = "agent-space-browser-requester";
  const encoder = new TextEncoder();
  const status = document.getElementById("browser-requester-status");
  const b64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const canonical = (value) => {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
    return "{" + Object.keys(value).sort().map((key) => JSON.stringify(key) + ":" + canonical(value[key])).join(",") + "}";
  };
  const joinBytes = (...parts) => {
    const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  };
  const signatureFor = async (privateKey, body) => {
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, encoder.encode(canonical(body)));
    return b64url(signature);
  };
  const signBody = async (privateKey, body, signatureKey) => {
    return { ...body, [signatureKey]: await signatureFor(privateKey, body) };
  };
  const newRequesterBundle = async () => {
    const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", joinBytes(encoder.encode("asp-agent-id-v1"), new Uint8Array([0]), spki)));
    const privateJwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
    const descriptor = await signBody(keys.privateKey, {
      alias: "agent://browser/requester",
      aid: "aid:ed25519:" + b64url(digest),
      public_key_spki: b64url(spki),
      transports: ["browser://local"],
      capabilities: ["summarize.text"],
      policy: {}
    }, "descriptor_signature");
    return { descriptor, privateJwk, privateKey: keys.privateKey };
  };
  const render = () => {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    status.textContent = saved ? "aid: " + saved.descriptor.aid : "No browser requester key";
  };
  document.getElementById("browser-generate-key").onclick = async () => {
    const bundle = await newRequesterBundle();
    localStorage.setItem(storageKey, JSON.stringify({ descriptor: bundle.descriptor, privateJwk: bundle.privateJwk }));
    render();
  };
  document.getElementById("browser-clear-key").onclick = () => {
    localStorage.removeItem(storageKey);
    render();
  };
  document.getElementById("browser-export-key").onclick = () => {
    const saved = localStorage.getItem(storageKey);
    if (!saved) {
      status.textContent = "No browser requester key";
      return;
    }
    document.getElementById("browser-key-bundle").value = JSON.stringify(JSON.parse(saved), null, 2);
  };
  document.getElementById("browser-import-key").onclick = () => {
    try {
      const bundle = JSON.parse(document.getElementById("browser-key-bundle").value);
      if (!bundle || !bundle.descriptor || !bundle.privateJwk) throw new Error("Invalid browser requester key bundle");
      localStorage.setItem(storageKey, JSON.stringify(bundle));
      render();
    } catch (error) {
      status.textContent = error.message;
    }
  };
  document.getElementById("browser-rotate-key").onclick = async () => {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (!saved) {
      status.textContent = "No browser requester key";
      return;
    }
    const previousKey = await crypto.subtle.importKey("jwk", saved.privateJwk, { name: "Ed25519" }, true, ["sign"]);
    const next = await newRequesterBundle();
    const body = { previous_aid: saved.descriptor.aid, next_aid: next.descriptor.aid };
    const rotation_proof = {
      ...body,
      previous_signature: await signatureFor(previousKey, body),
      next_signature: await signatureFor(next.privateKey, body)
    };
    localStorage.setItem(storageKey, JSON.stringify({ descriptor: next.descriptor, privateJwk: next.privateJwk, previous_descriptor: saved.descriptor, rotation_proof }));
    render();
  };
  document.getElementById("browser-rebind-key").onclick = async () => {
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (!saved || !saved.previous_descriptor || !saved.rotation_proof) {
      status.textContent = "Rotate key before binding alias";
      return;
    }
    const token = document.getElementById("browser-token").value;
    const headers = { "content-type": "application/json" };
    if (token) headers.authorization = "Bearer " + token;
    const response = await fetch("/api/requester/rebindings", {
      method: "POST",
      headers,
      body: JSON.stringify({ previous_descriptor: saved.previous_descriptor, next_descriptor: saved.descriptor, rotation_proof: saved.rotation_proof })
    });
    status.textContent = response.ok ? JSON.stringify(await response.json(), null, 2) : await response.text();
  };
  document.getElementById("browser-draft-form").onsubmit = async (event) => {
    event.preventDefault();
    const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
    if (!saved) {
      status.textContent = "No browser requester key";
      return;
    }
    const privateKey = await crypto.subtle.importKey("jwk", saved.privateJwk, { name: "Ed25519" }, true, ["sign"]);
    const task = await signBody(privateKey, {
      task_id: document.getElementById("browser-task-id").value,
      from: saved.descriptor.aid,
      to: document.getElementById("browser-task-to").value,
      intent: document.getElementById("browser-task-intent").value,
      scope: { network: false, write: [] },
      budget: { tokens: 1000 }
    }, "signature");
    const token = document.getElementById("browser-token").value;
    const headers = { "content-type": "application/json" };
    if (token) headers.authorization = "Bearer " + token;
    const response = await fetch("/api/queue/drafts", {
      method: "POST",
      headers,
      body: JSON.stringify({ requester: saved.descriptor, task })
    });
    status.textContent = response.ok ? JSON.stringify(await response.json(), null, 2) : await response.text();
  };
  render();
})();
</script>`
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

func loadHumanActorPolicy(path string) (map[string][]string, map[string][]string, map[string]string, error) {
	if path == "" {
		return nil, nil, nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var policy struct {
		QueueActions     map[string][]string `json:"queue_actions"`
		ApprovalActions  map[string][]string `json:"approval_actions"`
		ApprovalSessions map[string]string   `json:"approval_sessions"`
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, nil, nil, err
	}
	return policy.QueueActions, policy.ApprovalActions, policy.ApprovalSessions, nil
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

func (f Fixture) humanGatewayRequester() (map[string]any, error) {
	publicKey := f.AuthorityPrivateKey.Public().(ed25519.PublicKey)
	encoded, der, err := publicKeySPKI(publicKey)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"alias":           "agent://human-gateway/local",
		"aid":             aidFromSPKI(der),
		"public_key_spki": encoded,
		"transports":      []string{"human-gateway.local"},
		"capabilities":    []string{"queue.draft"},
		"policy":          map[string]any{"local_proof": true},
	}
	return signBodyWithKey(f.AuthorityPrivateKey, body, "descriptor_signature"), nil
}

func (f Fixture) requesterAliasRebindingProof(previous, next, rotationProof map[string]any) (map[string]any, error) {
	if previous["alias"] != next["alias"] {
		return nil, errors.New("alias rebinding requires matching aliases")
	}
	if err := verifyAgentRotationProof(rotationProof, previous, next); err != nil {
		return nil, err
	}
	body := map[string]any{
		"zone":         f.Authority["zid"],
		"alias":        previous["alias"],
		"previous_aid": previous["aid"],
		"next_aid":     next["aid"],
	}
	proof := signBodyWithKey(f.AuthorityPrivateKey, body, "zone_signature")
	proof["agent_rotation_proof"] = rotationProof
	return proof, nil
}

func (f Fixture) writeRequesterRegistry(descriptor map[string]any) error {
	registry, err := readRequesterRegistry()
	if err != nil {
		return err
	}
	registry["zone"] = f.Authority
	if _, ok := registry["revocations"].([]any); !ok {
		registry["revocations"] = []any{}
	}
	agents, _ := registry["agents"].([]any)
	next := map[string]any{
		"descriptor":   descriptor,
		"zone_binding": f.zoneBindingForDescriptor(descriptor),
	}
	replaced := false
	for index, item := range agents {
		entry, _ := item.(map[string]any)
		existing, _ := entry["descriptor"].(map[string]any)
		if existing["alias"] == descriptor["alias"] {
			agents[index] = next
			replaced = true
			break
		}
	}
	if !replaced {
		agents = append(agents, next)
	}
	registry["agents"] = agents
	return writeJSONStateFile(requesterRegistryPath, registry)
}

func readRequesterRegistry() (map[string]any, error) {
	data, err := os.ReadFile(requesterRegistryPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{"revocations": []any{}, "agents": []any{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var registry map[string]any
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, err
	}
	return registry, nil
}

func requesterRegistryAgents(registry map[string]any) []map[string]any {
	items, _ := registry["agents"].([]any)
	agents := []map[string]any{}
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			agents = append(agents, entry)
		}
	}
	return agents
}

func readRequesterRebindingHistory() ([]map[string]any, error) {
	data, err := os.ReadFile(requesterRebindingHistoryPath)
	if errors.Is(err, os.ErrNotExist) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	var rebindings []map[string]any
	if err := json.Unmarshal(data, &rebindings); err != nil {
		return nil, err
	}
	return rebindings, nil
}

func (f Fixture) appendRequesterRebindingHistory(proof map[string]any) error {
	rebindings, err := readRequesterRebindingHistory()
	if err != nil {
		return err
	}
	rebindings = append(rebindings, map[string]any{
		"zone":                  proof["zone"],
		"alias":                 proof["alias"],
		"previous_aid":          proof["previous_aid"],
		"next_aid":              proof["next_aid"],
		"proof_digest":          digestHex(proof),
		"alias_rebinding_proof": proof,
	})
	return writeJSONStateFile(requesterRebindingHistoryPath, rebindings)
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
	return f.zoneBindingForDescriptor(worker.Descriptor)
}

func (f Fixture) zoneBindingForDescriptor(descriptor map[string]any) map[string]any {
	return signBody(f.AuthorityPrivateKey, map[string]any{
		"zone":  f.Authority["zid"],
		"alias": descriptor["alias"],
		"aid":   descriptor["aid"],
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

func (f Fixture) queueActionGrant(action, taskID string, task map[string]any) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"action":               action,
		"task_id":              taskID,
		"task_digest":          digestHex(task),
		"actor":                "human://local",
		"authority":            f.Authority["zid"],
		"authority_descriptor": f.Authority,
		"scope":                map[string]any{"actions": []any{action}},
		"expires_at":           "2099-01-01T00:00:00Z",
	}, "grant_signature")
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

func (f Fixture) executeTask(send sendFunc, origin map[string]any, worker *Worker, task map[string]any, parentCheckpoint any, restoredStateDigest string, retryOf any, requireHumanApproval bool, onReceipt func(map[string]any) error) error {
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
		if requireHumanApproval {
			if err := f.writeApprovalState(taskID, "pending", approvals, "", nil, approvalExpiresAt(task)); err != nil {
				return err
			}
		}
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.required", "task_id": taskID, "reasons": approvals}); err != nil {
			return err
		}
		grant := f.approvalGrant(taskID, approvals, "human://go-gateway/operator")
		if requireHumanApproval {
			var err error
			grant, err = f.waitForApproval(ctx, taskID)
			if err != nil {
				return err
			}
		}
		approvalGrants = append(approvalGrants, grant)
		if err := f.sendTaskEvent(send, map[string]any{"type": "approval.granted", "task_id": taskID, "by": grant["by"], "reasons": approvals, "grant": grant}); err != nil {
			return err
		}
	}
	if err := validateSandboxClaim(worker.Profile); err != nil {
		_ = f.writeTaskState(taskID, "failed", worker, map[string]any{"error": err.Error()})
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.started", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	if err := f.writeTaskState(taskID, "running", worker, map[string]any{}); err != nil {
		return err
	}
	policyScope := taskPolicyScope(worker.Profile, worker.Descriptor, task)
	policyDigest := digestHex(policyScope)
	checkpoint := worker.checkpoint(task, parentCheckpoint, restoredStateDigest, 3+len(approvals)*2, policyDigest)
	if err := f.sendTaskEvent(send, map[string]any{"type": "checkpoint.created", "task_id": taskID, "checkpoint": checkpoint}); err != nil {
		return err
	}

	artifactURI := "artifact://local/" + taskID + "/go-summary.md"
	toolName, artifactText, sandbox, err := runTool(ctx, worker.Profile, task, origin, f.ArtifactStoreDir, f.LiveTranscriptDir)
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
	artifactManifest, err := writeArtifact(artifactURI, artifactText, f.ArtifactStoreDir)
	if err != nil {
		return err
	}
	artifactRefs := []string{artifactURI}
	artifactManifests := []map[string]any{artifactManifest}
	if transcriptRef := optionalString(sandbox["tool_transcript_ref"]); transcriptRef != "" {
		transcriptManifest, ok := sandbox["tool_transcript_manifest"].(map[string]any)
		if !ok {
			return errors.New("tool transcript manifest missing")
		}
		artifactRefs = append(artifactRefs, transcriptRef)
		artifactManifests = append(artifactManifests, transcriptManifest)
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "artifact.created", "task_id": taskID, "uri": artifactURI, "manifest": artifactManifest}); err != nil {
		return err
	}
	if err := f.sendTaskEvent(send, map[string]any{"type": "task.completed", "task_id": taskID, "by": worker.Descriptor["aid"], "zone": f.Authority["zid"]}); err != nil {
		return err
	}
	sandboxProof := f.sandboxProof(taskID, worker, sandbox, policyDigest, sandboxClaim)

	receipt := map[string]any{
		"task_id":            taskID,
		"from":               task["from"],
		"origin_zone":        origin["zid"],
		"executing_zone":     f.Authority["zid"],
		"to":                 worker.Descriptor["aid"],
		"artifact_refs":      artifactRefs,
		"artifact_manifests": artifactManifests,
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
	if restoredStateDigest != "" {
		receipt["restored_state_digest"] = restoredStateDigest
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
	if onReceipt != nil {
		if err := onReceipt(signedReceipt); err != nil {
			return err
		}
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

func (w *Worker) checkpoint(task map[string]any, parent any, restoredStateDigest string, eventIndex int, policyDigest string) map[string]any {
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
	if restoredStateDigest != "" {
		body["restored_state_digest"] = restoredStateDigest
	}
	body["checkpoint_id"] = "checkpoint:sha256:" + digestHex(body)
	return signBodyWithKey(w.PrivateKey, body, "checkpoint_signature")
}

func (f Fixture) approvalGrant(taskID string, reasons []string, by string) map[string]any {
	return signBodyWithKey(f.AuthorityPrivateKey, map[string]any{
		"task_id":   taskID,
		"authority": f.Authority["zid"],
		"by":        by,
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

func runTool(ctx context.Context, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, string, map[string]any, error) {
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
		text, sandbox, err := runExternalTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, text, sandbox, err
	case "mcp.stdio":
		text, sandbox, err := runMCPTool(ctx, profile, task, origin, artifactStoreDir, liveTranscriptDir)
		return tool, text, sandbox, err
	default:
		return tool, "# Go Tool Output\n\nTask: " + taskID + "\nOrigin: " + fmt.Sprint(origin["zid"]) + "\nOutput: " + intent + "\n", inProcessSandbox(), nil
	}
}

func inProcessSandbox() map[string]any {
	return map[string]any{"mode": "in-process"}
}

func validateSandboxClaim(profile WorkerProfile) error {
	if profile.SandboxClaim == "" {
		return nil
	}
	if profile.SandboxClaim == expectedSandboxMode(profile) {
		return nil
	}
	return errors.New("unsupported sandbox claim: " + profile.SandboxClaim)
}

func expectedSandboxMode(profile WorkerProfile) string {
	switch profile.Tool {
	case "external.stdio", "mcp.stdio":
		return "local-temp-dir"
	default:
		return "in-process"
	}
}

func newToolSandbox(kind string, toolCommand []string) (string, map[string]any, func(), error) {
	dir, err := os.MkdirTemp("", "agnet-"+kind+"-*")
	if err != nil {
		return "", nil, nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "cache"), 0o755); err != nil {
		return "", nil, nil, err
	}
	env := sandboxEnv(dir)
	sandbox := map[string]any{
		"mode":            "local-temp-dir",
		"isolation_level": "local-process",
		"kind":            kind,
		"cwd":             dir,
		"env":             env,
		"network":         "not_granted",
		"cleanup":         "remove-all",
	}
	if len(toolCommand) > 0 {
		sandbox["tool_command_digest"] = digestHex(toolCommand)
		executable := toolCommand[0]
		if !filepath.IsAbs(executable) {
			executable, err = exec.LookPath(executable)
			if err != nil {
				return "", nil, nil, err
			}
		}
		data, err := os.ReadFile(executable)
		if err != nil {
			return "", nil, nil, err
		}
		sandbox["tool_binary_digest"] = digestBytesHex(data)
	}
	return dir, sandbox, func() { _ = os.RemoveAll(dir) }, nil
}

func sandboxEnv(dir string) []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"HOME=" + dir,
		"TMPDIR=" + dir,
		"XDG_CACHE_HOME=" + filepath.Join(dir, "cache"),
	}
}

type liveTranscriptWriter struct {
	file   *os.File
	taskID string
}

func newLiveTranscriptWriter(dir, taskID string) (*liveTranscriptWriter, func(), error) {
	if dir == "" {
		return nil, func() {}, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, err
	}
	file, err := os.Create(filepath.Join(dir, url.PathEscape(taskID)+".ndjson"))
	if err != nil {
		return nil, nil, err
	}
	return &liveTranscriptWriter{file: file, taskID: taskID}, func() { _ = file.Close() }, nil
}

func (w *liveTranscriptWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := json.NewEncoder(w.file).Encode(map[string]any{"type": "stdout.chunk", "task_id": w.taskID, "text": string(p)}); err != nil {
		return 0, err
	}
	_ = w.file.Sync()
	return len(p), nil
}

func (w *liveTranscriptWriter) WriteMCPResponse(method string, response map[string]any) error {
	if w == nil {
		return nil
	}
	if err := json.NewEncoder(w.file).Encode(map[string]any{"type": "mcp.response", "task_id": w.taskID, "method": method, "response": response}); err != nil {
		return err
	}
	_ = w.file.Sync()
	return nil
}

func runExternalTool(parent context.Context, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, map[string]any, error) {
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
	cmd.Env = sandboxEnv(dir)
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
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	liveWriter, closeLive, err := newLiveTranscriptWriter(liveTranscriptDir, fmt.Sprint(task["task_id"]))
	if err != nil {
		return "", nil, err
	}
	defer closeLive()
	if err := cmd.Start(); err != nil {
		return "", nil, err
	}
	var output bytes.Buffer
	writers := []io.Writer{&output}
	if liveWriter != nil {
		writers = append(writers, liveWriter)
	}
	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.MultiWriter(writers...), stdout)
		copyDone <- err
	}()
	err = cmd.Wait()
	if copyErr := <-copyDone; copyErr != nil && err == nil {
		err = copyErr
	}
	if ctx.Err() == context.Canceled {
		return "", nil, errors.New("external tool cancelled")
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", nil, errors.New("external tool timed out")
	}
	transcriptData := output.Bytes()
	sandbox["tool_transcript_digest"] = digestBytesHex(transcriptData)
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", nil, errors.New("external tool failed: " + message)
	}
	transcriptURI := "artifact://local/" + fmt.Sprint(task["task_id"]) + "/tool-transcript.json"
	transcriptManifest, err := writeArtifactBytes(transcriptURI, transcriptData, "application/json; charset=utf-8", artifactStoreDir)
	if err != nil {
		return "", nil, err
	}
	sandbox["tool_transcript_ref"] = transcriptURI
	sandbox["tool_transcript_manifest"] = transcriptManifest
	var result map[string]any
	if err := json.Unmarshal(transcriptData, &result); err != nil {
		return "", nil, err
	}
	text, ok := result["text"].(string)
	if !ok || text == "" {
		return "", nil, errors.New("external tool text missing")
	}
	return text, sandbox, nil
}

func runMCPTool(parent context.Context, profile WorkerProfile, task, origin map[string]any, artifactStoreDir, liveTranscriptDir string) (string, map[string]any, error) {
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
	cmd.Env = sandboxEnv(dir)
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
	liveWriter, closeLive, err := newLiveTranscriptWriter(liveTranscriptDir, fmt.Sprint(task["task_id"]))
	if err != nil {
		return "", nil, err
	}
	defer closeLive()
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
	if err := liveWriter.WriteMCPResponse("initialize", initializeResponse); err != nil {
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
	if _, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 2, "resources/list", "resources", "mcp_resources"); err != nil {
		return "", nil, err
	}
	if _, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 3, "prompts/list", "prompts", "mcp_prompts"); err != nil {
		return "", nil, err
	}
	tools, err := recordMCPListEvidence(writeRPC, scanner, liveWriter, sandbox, 4, "tools/list", "tools", "mcp_tools")
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
	if err := liveWriter.WriteMCPResponse("tools/call", response); err != nil {
		return "", nil, err
	}
	transcriptData, err := json.Marshal(response)
	if err != nil {
		return "", nil, err
	}
	sandbox["tool_transcript_digest"] = digestBytesHex(transcriptData)
	transcriptURI := "artifact://local/" + fmt.Sprint(task["task_id"]) + "/tool-transcript.json"
	transcriptManifest, err := writeArtifactBytes(transcriptURI, transcriptData, "application/json; charset=utf-8", artifactStoreDir)
	if err != nil {
		return "", nil, err
	}
	sandbox["tool_transcript_ref"] = transcriptURI
	sandbox["tool_transcript_manifest"] = transcriptManifest
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

func recordMCPListEvidence(writeRPC func(map[string]any) error, scanner *bufio.Scanner, liveWriter *liveTranscriptWriter, sandbox map[string]any, id float64, method, field, prefix string) ([]any, error) {
	if err := writeRPC(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": map[string]any{}}); err != nil {
		return nil, err
	}
	response, err := readRPCResponse(scanner, id)
	if err != nil {
		return nil, err
	}
	if err := liveWriter.WriteMCPResponse(method, response); err != nil {
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

func writeJSONStateFile(path string, body any) error {
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o644)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(perm); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	cleanup = false
	return nil
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
	// ponytail: one JSON file per task; replace with an indexed store when scheduling needs queries.
	return writeJSONStateFile(filepath.Join(f.TaskStateDir, url.PathEscape(taskID)+".json"), body)
}

func approvalExpiresAt(task map[string]any) string {
	if expiresAt := optionalString(task["approval_expires_at"]); expiresAt != "" {
		return expiresAt
	}
	return time.Now().Add(60 * time.Second).UTC().Format(time.RFC3339Nano)
}

func (f Fixture) writeApprovalState(taskID, status string, reasons []string, by string, approval map[string]any, expiresAt string) error {
	if f.ApprovalDir == "" {
		return nil
	}
	body := map[string]any{
		"task_id": taskID,
		"status":  status,
		"reasons": stringsAny(reasons),
	}
	if expiresAt != "" {
		body["expires_at"] = expiresAt
	}
	if by != "" {
		body["by"] = by
	}
	if approval != nil {
		body["approval"] = approval
	}
	return writeJSONStateFile(filepath.Join(f.ApprovalDir, url.PathEscape(taskID)+".json"), body)
}

func (f Fixture) readApprovalState(taskID string) (map[string]any, error) {
	if f.ApprovalDir == "" {
		return nil, errors.New("approval state unavailable")
	}
	data, err := os.ReadFile(filepath.Join(f.ApprovalDir, url.PathEscape(taskID)+".json"))
	if err != nil {
		return nil, err
	}
	var state map[string]any
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return state, nil
}

func (f Fixture) applyApprovalAction(taskID, actor, action string) (map[string]any, error) {
	approvalStateMu.Lock()
	defer approvalStateMu.Unlock()
	state, err := f.readApprovalState(taskID)
	if err != nil {
		return nil, err
	}
	if optionalString(state["status"]) != "pending" {
		return nil, errors.New("approval is not pending: " + taskID)
	}
	reasons := stringsFromAny(state["reasons"])
	expiresAt := optionalString(state["expires_at"])
	if approvalExpired(expiresAt) {
		if err := f.writeApprovalState(taskID, "expired", reasons, "", nil, expiresAt); err != nil {
			return nil, err
		}
		return nil, errors.New("approval expired: " + taskID)
	}
	if action == "deny" {
		if err := f.writeApprovalState(taskID, "denied", reasons, actor, nil, expiresAt); err != nil {
			return nil, err
		}
		return map[string]any{"task_id": taskID, "status": "denied", "by": actor, "reasons": stringsAny(reasons), "expires_at": expiresAt}, nil
	}
	grant := f.approvalGrant(taskID, reasons, actor)
	if err := f.writeApprovalState(taskID, "approved", reasons, actor, grant, expiresAt); err != nil {
		return nil, err
	}
	return grant, nil
}

func approvalExpired(expiresAt string) bool {
	if expiresAt == "" {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return true
	}
	return !time.Now().UTC().Before(parsed)
}

func (f Fixture) waitForApproval(ctx context.Context, taskID string) (map[string]any, error) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := f.readApprovalState(taskID)
		if err == nil {
			switch optionalString(state["status"]) {
			case "approved":
				approval, _ := state["approval"].(map[string]any)
				if approval == nil {
					return nil, errors.New("approved task missing approval grant: " + taskID)
				}
				return approval, nil
			case "denied":
				return nil, errors.New("approval denied: " + taskID)
			case "pending":
				if approvalExpired(optionalString(state["expires_at"])) {
					approvalStateMu.Lock()
					if writeErr := f.writeApprovalState(taskID, "expired", stringsFromAny(state["reasons"]), "", nil, optionalString(state["expires_at"])); writeErr != nil {
						approvalStateMu.Unlock()
						return nil, writeErr
					}
					approvalStateMu.Unlock()
					return nil, errors.New("approval expired: " + taskID)
				}
			case "expired":
				return nil, errors.New("approval expired: " + taskID)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (f Fixture) writeQueueItem(origin map[string]any, worker *Worker, task map[string]any, status string, extra map[string]any) error {
	if f.QueueDir == "" {
		return nil
	}
	taskID := fmt.Sprint(task["task_id"])
	body := map[string]any{
		"task_id":     taskID,
		"status":      status,
		"worker":      worker.Descriptor["aid"],
		"origin_zone": origin["zid"],
		"task_digest": digestHex(task),
	}
	for key, value := range extra {
		body[key] = value
	}
	// ponytail: one queue file per task; replace with leases when multiple workers can drain it.
	return writeJSONStateFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"), body)
}

func (f Fixture) readQueueItem(taskID string) (map[string]any, error) {
	if f.QueueDir == "" {
		return nil, errors.New("queue unavailable")
	}
	data, err := os.ReadFile(filepath.Join(f.QueueDir, url.PathEscape(taskID)+".json"))
	if err != nil {
		return nil, err
	}
	var item map[string]any
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, err
	}
	return item, nil
}

func (f Fixture) enqueueQueueItem(origin map[string]any, frame map[string]any) (string, any, error) {
	return f.enqueueQueueItemWithExtra(origin, frame, map[string]any{})
}

func (f Fixture) enqueueResumeQueueItem(origin map[string]any, frame map[string]any) (string, any, error) {
	checkpointID := fmt.Sprint(frame["checkpoint_id"])
	if checkpointID == "" || checkpointID == "<nil>" {
		return "", nil, errors.New("resume checkpoint_id missing")
	}
	if err := f.requireCheckpoint(checkpointID); err != nil {
		return "", nil, err
	}
	return f.enqueueQueueItemWithExtra(origin, frame, map[string]any{"resume_checkpoint": checkpointID})
}

func (f Fixture) enqueueQueueItemWithExtra(origin map[string]any, frame map[string]any, extra map[string]any) (string, any, error) {
	worker, task, err := f.verifyTaskOpen(frame)
	if err != nil {
		return "", nil, err
	}
	requester, _ := frame["requester"].(map[string]any)
	body := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task}
	for key, value := range extra {
		body[key] = value
	}
	if err := f.writeQueueItem(origin, worker, task, "queued", body); err != nil {
		return "", nil, err
	}
	return fmt.Sprint(task["task_id"]), worker.Descriptor["aid"], nil
}

func (f Fixture) claimQueueItem(taskID, owner string, leaseSeconds int) (string, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return "", err
	}
	if optionalString(item["status"]) != "queued" {
		return "", errors.New("queue item is not queued: " + taskID)
	}
	if queueRetryBackoffActive(item) {
		return "", errors.New("queue retry backoff active: " + taskID)
	}
	return f.writeClaimedQueueItem(taskID, owner, leaseSeconds, item)
}

func (f Fixture) retryQueueItem(origin map[string]any, frame map[string]any, retryAfterSeconds int) (string, error) {
	retryOf := fmt.Sprint(frame["retry_of"])
	if retryOf == "" || retryOf == "<nil>" {
		return "", errors.New("queue retry_of missing")
	}
	parent, err := f.readQueueItem(retryOf)
	if err != nil {
		return "", err
	}
	if optionalString(parent["status"]) != "failed" {
		return "", errors.New("queue retry parent is not failed: " + retryOf)
	}
	worker, task, err := f.verifyTaskOpen(frame)
	if err != nil {
		return "", err
	}
	taskID := fmt.Sprint(task["task_id"])
	attempt := 1
	if parentAttempt, ok := parent["retry_attempt"].(float64); ok {
		attempt = int(parentAttempt) + 1
	}
	retryAfterAt := time.Now().Add(time.Duration(retryAfterSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
	requester, _ := frame["requester"].(map[string]any)
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "retry_of": retryOf, "retry_attempt": attempt, "retry_after_at": retryAfterAt}
	if err := f.writeQueueItem(origin, worker, task, "queued", extra); err != nil {
		return "", err
	}
	return taskID, nil
}

func (f Fixture) applyQueueAction(action map[string]any) (map[string]any, error) {
	switch optionalString(action["action"]) {
	case "enqueue":
		origin, _ := action["origin_zone"].(map[string]any)
		if len(origin) == 0 {
			return nil, errors.New("queue action origin_zone missing")
		}
		taskID, workerID, err := f.enqueueQueueItem(origin, action)
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "enqueue", "task_id": taskID, "worker": workerID}, nil
	case "claim":
		taskID := fmt.Sprint(action["task_id"])
		if taskID == "" || taskID == "<nil>" {
			return nil, errors.New("queue action task_id missing")
		}
		owner := fmt.Sprint(action["owner"])
		if owner == "" || owner == "<nil>" {
			return nil, errors.New("queue action owner missing")
		}
		leaseID, err := f.claimQueueItem(taskID, owner, frameSeconds(action, "lease_seconds", 60))
		if err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "claim", "task_id": taskID, "lease_id": leaseID, "owner": owner}, nil
	case "drain":
		taskID := fmt.Sprint(action["task_id"])
		if taskID == "" || taskID == "<nil>" {
			return nil, errors.New("queue action task_id missing")
		}
		leaseID := fmt.Sprint(action["lease_id"])
		if leaseID == "" || leaseID == "<nil>" {
			return nil, errors.New("queue action lease_id missing")
		}
		if err := f.drainQueueItem(func(map[string]any) {}, taskID, leaseID); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "action": "drain", "task_id": taskID}, nil
	default:
		return nil, errors.New("unsupported queue action")
	}
}

func (f Fixture) requireQueueActionGrant(action map[string]any) error {
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return errors.New("queue action grant missing")
	}
	authority, ok := grant["authority_descriptor"].(map[string]any)
	if !ok {
		return errors.New("queue action grant authority descriptor missing")
	}
	if err := verifyZoneDescriptor(authority); err != nil {
		return err
	}
	if grant["authority"] != authority["zid"] {
		return errors.New("queue action grant authority mismatch")
	}
	if grant["action"] != action["action"] {
		return errors.New("queue action grant action mismatch")
	}
	if !queueActionGrantAllows(grant, optionalString(action["action"])) {
		return errors.New("queue action grant scope mismatch")
	}
	if optionalString(grant["actor"]) == "" {
		return errors.New("queue action grant actor missing")
	}
	if optionalString(action["actor"]) == "" {
		return errors.New("queue action actor missing")
	}
	if grant["actor"] != action["actor"] {
		return errors.New("queue action grant actor mismatch")
	}
	if !f.queueActionActorAllowed(optionalString(action["actor"]), optionalString(action["action"])) {
		return errors.New("queue action actor policy denied")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, optionalString(grant["expires_at"]))
	if err != nil {
		return errors.New("queue action grant expires_at invalid")
	}
	if !time.Now().UTC().Before(expiresAt) {
		return errors.New("queue action grant expired")
	}
	if grant["task_id"] != queueActionTaskID(action, nil) {
		return errors.New("queue action grant task mismatch")
	}
	task, _ := action["task"].(map[string]any)
	expectedTaskDigest := any(nil)
	if task != nil {
		expectedTaskDigest = digestHex(task)
	}
	if grant["task_digest"] != expectedTaskDigest {
		return errors.New("queue action grant task digest mismatch")
	}
	authorityKey, _, err := publicKey(authority)
	if err != nil {
		return err
	}
	if err := verifyMapSignature(authorityKey, grant, "grant_signature"); err != nil {
		return errors.New("queue action grant signature verification failed")
	}
	grantDigest := digestHex(grant)
	return f.consumeQueueActionGrant(grantDigest, action)
}

func queueActionGrantAllows(grant map[string]any, action string) bool {
	scope, _ := grant["scope"].(map[string]any)
	for _, item := range stringsFromAny(scope["actions"]) {
		if item == action {
			return true
		}
	}
	return false
}

func (f Fixture) queueActionActorAllowed(actor, action string) bool {
	if len(f.QueueActorPolicy) == 0 {
		return actor == "human://local" && (action == "enqueue" || action == "claim" || action == "drain")
	}
	for _, allowed := range f.QueueActorPolicy[actor] {
		if allowed == action {
			return true
		}
	}
	return false
}

func (f Fixture) approvalActorAllowed(actor, action string) bool {
	if len(f.ApprovalActorPolicy) == 0 {
		return actor == "human://local" && (action == "approve" || action == "deny")
	}
	for _, allowed := range f.ApprovalActorPolicy[actor] {
		if allowed == action {
			return true
		}
	}
	return false
}

func (f Fixture) approvalActionsFor(actor string) []string {
	if actor == "" {
		return []string{}
	}
	if len(f.ApprovalActorPolicy) == 0 {
		if actor == "human://local" {
			return []string{"approve", "deny"}
		}
		return []string{}
	}
	return append([]string{}, f.ApprovalActorPolicy[actor]...)
}

func (f Fixture) approvalSessionActor(r *http.Request) string {
	if len(f.ApprovalSessions) == 0 {
		return ""
	}
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return f.ApprovalSessions[strings.TrimPrefix(header, "Bearer ")]
}

func (f Fixture) consumeQueueActionGrant(grantDigest string, action map[string]any) error {
	if f.Audit == nil || f.Audit.Path == "" {
		return nil
	}
	dir := queueGrantDirForAudit(f.Audit.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, grantDigest+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("queue action grant replay")
	}
	if err != nil {
		return err
	}
	defer file.Close()
	record := map[string]any{
		"grant_digest": grantDigest,
		"action":       optionalString(action["action"]),
		"task_id":      queueActionTaskID(action, nil),
		"actor":        queueActionActor(action),
		"consumed_at":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	return err
}

func (f Fixture) recordQueueAction(action map[string]any, result map[string]any, actionErr error) error {
	record := map[string]any{
		"kind":         "go_queue_action",
		"action":       optionalString(action["action"]),
		"task_id":      queueActionTaskID(action, result),
		"source":       "human_gateway.local",
		"grant_digest": queueActionGrantDigest(action),
		"actor":        queueActionActor(action),
	}
	if actorPolicyResult := f.queueActionActorPolicyResult(action); actorPolicyResult != "" {
		record["actor_policy_result"] = actorPolicyResult
	}
	if actionErr != nil {
		record["status"] = "error"
		record["error"] = actionErr.Error()
	} else {
		record["status"] = "ok"
		record["result_digest"] = digestHex(result)
	}
	return f.appendAudit(record)
}
func queueActionGrantDigest(action map[string]any) any {
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return nil
	}
	return digestHex(grant)
}

func queueActionActor(action map[string]any) string {
	if actor := optionalString(action["actor"]); actor != "" {
		return actor
	}
	if grant, ok := action["action_grant"].(map[string]any); ok {
		return optionalString(grant["actor"])
	}
	return ""
}

func (f Fixture) queueActionActorPolicyResult(action map[string]any) string {
	actionName := optionalString(action["action"])
	grant, ok := action["action_grant"].(map[string]any)
	if !ok {
		return ""
	}
	authority, ok := grant["authority_descriptor"].(map[string]any)
	if !ok || verifyZoneDescriptor(authority) != nil {
		return ""
	}
	if grant["authority"] != authority["zid"] || grant["action"] != action["action"] || !queueActionGrantAllows(grant, actionName) {
		return ""
	}
	actor := optionalString(action["actor"])
	if actor == "" || optionalString(grant["actor"]) == "" || grant["actor"] != action["actor"] {
		return ""
	}
	if f.queueActionActorAllowed(actor, actionName) {
		return "allow"
	}
	return "deny"
}

func queueActionTaskID(action, result map[string]any) string {
	if taskID := optionalString(action["task_id"]); taskID != "" {
		return taskID
	}
	if taskID := optionalString(result["task_id"]); taskID != "" {
		return taskID
	}
	task, _ := action["task"].(map[string]any)
	return optionalString(task["task_id"])
}

func (f Fixture) reclaimQueueItem(taskID, owner string, leaseSeconds int) (string, error) {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return "", err
	}
	if optionalString(item["status"]) != "claimed" {
		return "", errors.New("queue item is not claimed: " + taskID)
	}
	if !queueLeaseExpired(item) {
		return "", errors.New("queue lease is still active: " + taskID)
	}
	return f.writeClaimedQueueItem(taskID, owner, leaseSeconds, item)
}

func (f Fixture) writeClaimedQueueItem(taskID, owner string, leaseSeconds int, item map[string]any) (string, error) {
	origin, _ := item["origin_zone_descriptor"].(map[string]any)
	requester, _ := item["requester"].(map[string]any)
	task, _ := item["task"].(map[string]any)
	worker, task, err := f.verifyTaskOpen(map[string]any{"requester": requester, "task": task})
	if err != nil {
		return "", err
	}
	leaseExpiresAt := time.Now().Add(time.Duration(leaseSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
	leaseID := "lease:sha256:" + digestHex(map[string]any{"task_id": taskID, "owner": owner, "task_digest": item["task_digest"], "lease_expires_at": leaseExpiresAt})
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "lease_owner": owner, "lease_id": leaseID, "lease_expires_at": leaseExpiresAt}
	copyQueueCarryFields(extra, item)
	if err := f.writeQueueItem(origin, worker, task, "claimed", extra); err != nil {
		return "", err
	}
	return leaseID, nil
}

func (f Fixture) drainQueueItem(send sendFunc, taskID, leaseID string) error {
	item, err := f.readQueueItem(taskID)
	if err != nil {
		return err
	}
	if optionalString(item["status"]) != "claimed" {
		return errors.New("queue item is not claimed: " + taskID)
	}
	if leaseID == "" || leaseID == "<nil>" || optionalString(item["lease_id"]) != leaseID {
		return errors.New("queue lease mismatch: " + taskID)
	}
	if queueLeaseExpired(item) {
		return errors.New("queue lease expired: " + taskID)
	}
	origin, _ := item["origin_zone_descriptor"].(map[string]any)
	requester, _ := item["requester"].(map[string]any)
	task, _ := item["task"].(map[string]any)
	worker, task, err := f.verifyTaskOpen(map[string]any{"requester": requester, "task": task})
	if err != nil {
		return err
	}
	extra := map[string]any{"origin_zone_descriptor": origin, "requester": requester, "task": task, "lease_owner": item["lease_owner"], "lease_id": item["lease_id"], "lease_expires_at": item["lease_expires_at"]}
	copyQueueCarryFields(extra, item)
	if err := f.writeQueueItem(origin, worker, task, "running", extra); err != nil {
		return err
	}
	var parentCheckpoint any
	restoredStateDigest := ""
	if checkpointID := optionalString(item["resume_checkpoint"]); checkpointID != "" {
		parent, err := f.checkpointByID(checkpointID)
		if err != nil {
			return err
		}
		parentCheckpoint = checkpointID
		restoredStateDigest = optionalString(parent["state_digest"])
	}
	err = f.executeTask(send, origin, worker, task, parentCheckpoint, restoredStateDigest, nil, true, func(receipt map[string]any) error {
		extra["receipt_digest"] = digestHex(receipt)
		return f.writeQueueItem(origin, worker, task, "completed", extra)
	})
	if err != nil {
		extra["error"] = err.Error()
		_ = f.writeQueueItem(origin, worker, task, "failed", extra)
		return err
	}
	return nil
}

func writeArtifact(uri, text, artifactStoreDir string) (map[string]any, error) {
	return writeArtifactBytes(uri, []byte(text), "text/markdown; charset=utf-8", artifactStoreDir)
}

func writeArtifactBytes(uri string, data []byte, mediaType, artifactStoreDir string) (map[string]any, error) {
	path, err := localArtifactPath(uri)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, err
	}
	sha := digestBytesHex(data)
	body := map[string]any{
		"uri":        uri,
		"sha256":     sha,
		"size":       float64(len(data)),
		"media_type": mediaType,
	}
	body["manifest_hash"] = digestHex(body)
	sidecar, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return nil, err
	}
	sidecar = append(sidecar, '\n')
	if err := os.WriteFile(path+".manifest.json", sidecar, 0o644); err != nil {
		return nil, err
	}
	digestRoots := []string{"artifacts"}
	if artifactStoreDir != "" {
		digestRoots = append(digestRoots, artifactStoreDir)
	}
	for _, root := range digestRoots {
		digestPath := filepath.Join(root, "by-sha256", sha)
		if err := os.MkdirAll(filepath.Dir(digestPath), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(digestPath, data, 0o644); err != nil {
			return nil, err
		}
		if err := os.WriteFile(digestPath+".manifest.json", sidecar, 0o644); err != nil {
			return nil, err
		}
		if root == artifactStoreDir {
			if err := appendArtifactStoreIndex(root, body); err != nil {
				return nil, err
			}
		}
	}
	return body, nil
}

func appendArtifactStoreIndex(root string, manifest map[string]any) error {
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(root, "objects.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(map[string]any{
		"uri":           manifest["uri"],
		"sha256":        manifest["sha256"],
		"size":          manifest["size"],
		"media_type":    manifest["media_type"],
		"manifest_hash": manifest["manifest_hash"],
	})
}

func localArtifactPath(uri string) (string, error) {
	const prefix = "artifact://local/"
	if !strings.HasPrefix(uri, prefix) {
		return "", errors.New("unsupported artifact uri: " + uri)
	}
	raw := strings.TrimPrefix(uri, prefix)
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if normalized == "" || strings.HasPrefix(normalized, "/") {
		return "", errors.New("invalid artifact uri path: " + uri)
	}
	parts := strings.Split(normalized, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("invalid artifact uri path: " + uri)
		}
	}
	return filepath.Join(append([]string{"artifacts"}, parts...)...), nil
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

func verifyAuditFile(path, artifactStoreDir string) error {
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
			if err := verifyReceiptRecord(record, artifactStoreDir); err != nil {
				return err
			}
		}
		prev = fmt.Sprint(entry["hash"])
	}
	return nil
}

func verifyReceiptFile(path, artifactStoreDir string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	if err := verifyReceiptRecord(record, artifactStoreDir); err != nil {
		return nil, err
	}
	receipt, _ := record["receipt"].(map[string]any)
	return map[string]any{"go_receipt_verify": "ok", "task_id": receipt["task_id"]}, nil
}

func planArtifactStoreGC(auditPath, artifactStoreDir string) (map[string]any, error) {
	if artifactStoreDir == "" {
		return nil, errors.New("artifact-store is required for gc plan")
	}
	if err := verifyAuditFile(auditPath, artifactStoreDir); err != nil {
		return nil, err
	}
	entries, err := readAuditEntries(auditPath)
	if err != nil {
		return nil, err
	}
	referenced := map[string]bool{}
	for _, entry := range entries {
		record, _ := entry["record"].(map[string]any)
		if record["kind"] != "go_fed_receipt" {
			continue
		}
		receipt, _ := record["receipt"].(map[string]any)
		for _, manifest := range mapsFromAny(receipt["artifact_manifests"]) {
			referenced[fmt.Sprint(manifest["sha256"])] = true
		}
	}
	index, err := readArtifactStoreIndex(filepath.Join(artifactStoreDir, "objects.ndjson"))
	if err != nil {
		return nil, err
	}
	var orphans []map[string]any
	for _, entry := range index {
		if !referenced[fmt.Sprint(entry["sha256"])] {
			orphans = append(orphans, entry)
		}
	}
	return map[string]any{"artifact_store_gc_plan": "ok", "orphans": orphans}, nil
}

func applyArtifactStoreGC(auditPath, artifactStoreDir string) (map[string]any, error) {
	plan, err := planArtifactStoreGC(auditPath, artifactStoreDir)
	if err != nil {
		return nil, err
	}
	orphans := mapsFromAny(plan["orphans"])
	var deleted []map[string]any
	for _, orphan := range orphans {
		sha := fmt.Sprint(orphan["sha256"])
		if sha == "" {
			continue
		}
		path := filepath.Join(artifactStoreDir, "by-sha256", sha)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := os.Remove(path + ".manifest.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		deleted = append(deleted, orphan)
	}
	return map[string]any{"artifact_store_gc_apply": "ok", "deleted": deleted}, nil
}

func readAuditEntries(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	out := []map[string]any{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
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

func verifyReceiptRecord(record map[string]any, artifactStoreDir string) error {
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
	if err := verifyArtifactManifests(receipt, artifactStoreDir); err != nil {
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

func verifyArtifactManifests(receipt map[string]any, artifactStoreDir string) error {
	refs := stringsFromAny(receipt["artifact_refs"])
	manifests := mapsFromAny(receipt["artifact_manifests"])
	if len(refs) != len(manifests) {
		return errors.New("receipt artifact manifest count mismatch")
	}
	var artifactStoreIndex []map[string]any
	if artifactStoreDir != "" && len(manifests) > 0 {
		index, err := readArtifactStoreIndex(filepath.Join(artifactStoreDir, "objects.ndjson"))
		if err != nil {
			return err
		}
		artifactStoreIndex = index
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
		path, err := localArtifactPath(refs[index])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sidecarData, err := os.ReadFile(path + ".manifest.json")
		if err != nil {
			return err
		}
		var sidecar map[string]any
		if err := json.Unmarshal(sidecarData, &sidecar); err != nil {
			return err
		}
		if digestHex(sidecar) != digestHex(manifest) {
			return errors.New("artifact manifest sidecar mismatch")
		}
		digestSidecarData, err := os.ReadFile(filepath.Join("artifacts", "by-sha256", fmt.Sprint(manifest["sha256"])) + ".manifest.json")
		if err != nil {
			return err
		}
		var digestSidecar map[string]any
		if err := json.Unmarshal(digestSidecarData, &digestSidecar); err != nil {
			return err
		}
		if digestHex(digestSidecar) != digestHex(manifest) {
			return errors.New("artifact digest sidecar mismatch")
		}
		if artifactStoreDir != "" {
			mirrorPath := filepath.Join(artifactStoreDir, "by-sha256", fmt.Sprint(manifest["sha256"]))
			mirrorData, err := os.ReadFile(mirrorPath)
			if err != nil {
				return err
			}
			mirrorSidecarData, err := os.ReadFile(mirrorPath + ".manifest.json")
			if err != nil {
				return err
			}
			var mirrorSidecar map[string]any
			if err := json.Unmarshal(mirrorSidecarData, &mirrorSidecar); err != nil {
				return err
			}
			if digestHex(mirrorSidecar) != digestHex(manifest) {
				return errors.New("artifact mirror sidecar mismatch")
			}
			if float64(len(mirrorData)) != manifest["size"] {
				return errors.New("artifact mirror bytes size mismatch")
			}
			if digestBytesHex(mirrorData) != manifest["sha256"] {
				return errors.New("artifact mirror bytes digest mismatch")
			}
			if !artifactStoreIndexContains(artifactStoreIndex, manifest) {
				return errors.New("artifact mirror index entry missing")
			}
		}
		if float64(len(data)) != manifest["size"] {
			return errors.New("artifact bytes size mismatch")
		}
		if digestBytesHex(data) != manifest["sha256"] {
			return errors.New("artifact bytes digest mismatch")
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

func readArtifactStoreIndex(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("artifact mirror index missing")
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var out []map[string]any
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry := map[string]any{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, errors.New("artifact mirror index invalid")
		}
		out = append(out, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func artifactStoreIndexContains(index []map[string]any, manifest map[string]any) bool {
	for _, entry := range index {
		matches := true
		for _, field := range []string{"uri", "sha256", "size", "media_type", "manifest_hash"} {
			if fmt.Sprint(entry[field]) != fmt.Sprint(manifest[field]) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func receiptArtifactManifest(receipt map[string]any, uri string) (map[string]any, error) {
	refs := stringsFromAny(receipt["artifact_refs"])
	manifests := mapsFromAny(receipt["artifact_manifests"])
	for index, ref := range refs {
		if ref == uri && index < len(manifests) {
			return manifests[index], nil
		}
	}
	return nil, errors.New("receipt artifact not found: " + uri)
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
	for _, key := range []string{"retry_of", "retry_attempt", "retry_after_at", "resume_checkpoint"} {
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
		entry := map[string]any{}
		for key, value := range zone {
			entry[key] = value
		}
		var revocations []any
		for _, revocation := range store.Revocations {
			if revocation["zone"] == zone["zid"] {
				revocations = append(revocations, revocation)
			}
		}
		if len(revocations) > 0 {
			entry["revocations"] = revocations
			if err := verifyZoneRevocations(entry, ""); err != nil {
				return nil, err
			}
		}
		out[fmt.Sprint(zone["zid"])] = entry
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
	if err := verifyZoneRevocations(known, fmt.Sprint(zone["zid"])); err != nil {
		return err
	}
	return nil
}

func verifyZoneRevocations(zone map[string]any, subject string) error {
	revocations, _ := zone["revocations"].([]any)
	for _, item := range revocations {
		revocation, ok := item.(map[string]any)
		if !ok {
			return errors.New("zone revocation invalid")
		}
		if revocation["zone"] != zone["zid"] {
			return errors.New("zone revocation issuer mismatch")
		}
		key, _, err := publicKey(zone)
		if err != nil {
			return err
		}
		if err := verifyMapSignature(key, revocation, "signature"); err != nil {
			return errors.New("zone revocation signature verification failed")
		}
		if revocation["subject"] == subject {
			return errors.New("zone revoked: " + subject)
		}
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

func verifyAgentRotationProof(proof, previous, next map[string]any) error {
	if err := verifyAgentDescriptor(previous); err != nil {
		return err
	}
	if err := verifyAgentDescriptor(next); err != nil {
		return err
	}
	body := map[string]any{
		"previous_aid": previous["aid"],
		"next_aid":     next["aid"],
	}
	if proof["previous_aid"] != body["previous_aid"] || proof["next_aid"] != body["next_aid"] {
		return errors.New("rotation proof aid mismatch")
	}
	previousKey, _, err := publicKey(previous)
	if err != nil {
		return err
	}
	nextKey, _, err := publicKey(next)
	if err != nil {
		return err
	}
	previousSigned := map[string]any{
		"previous_aid":       body["previous_aid"],
		"next_aid":           body["next_aid"],
		"previous_signature": proof["previous_signature"],
	}
	if err := verifyMapSignature(previousKey, previousSigned, "previous_signature"); err != nil {
		return err
	}
	nextSigned := map[string]any{
		"previous_aid":   body["previous_aid"],
		"next_aid":       body["next_aid"],
		"next_signature": proof["next_signature"],
	}
	return verifyMapSignature(nextKey, nextSigned, "next_signature")
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
