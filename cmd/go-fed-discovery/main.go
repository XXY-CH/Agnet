package main

import (
	"agnet/verifier"
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	listenHost := flag.String("listen-host", "127.0.0.1", "main federation TCP listen host")
	port := flag.String("port", "9090", "listen port")
	wsPort := flag.String("ws-port", "", "optional WebSocket listen port")
	humanPort := flag.String("human-port", "", "optional Human Gateway HTTP port")
	humanToken := flag.String("human-token", "", "optional Human Gateway bearer token for write actions")
	humanActorPolicyPath := flag.String("human-actor-policy", "", "optional Human Gateway actor policy JSON file")
	tlsCertPath := flag.String("tls-cert", "", "optional federation TCP TLS certificate file")
	tlsKeyPath := flag.String("tls-key", "", "optional federation TCP TLS key file")
	tlsClientCAPath := flag.String("tls-client-ca", "", "optional federation TCP client certificate CA file")
	artifactStoreDir := flag.String("artifact-store", "", "optional filesystem artifact mirror directory")
	fixturePath := flag.String("fixture", "test-vectors/asp-v1.5-capability-credential.json", "signed descriptor fixture")
	trustPath := flag.String("trusted", "state/go-fed-trusted-zones.json", "trusted origin zones")
	authorityStorePath := flag.String("authority-store", "state/keys/go-fed-authority", "managed authority key store directory")
	authorityPassphrasePath := flag.String("authority-passphrase-file", "state/keys/go-fed-authority.passphrase", "managed authority passphrase file")
	authorityRecordDigest := flag.String("authority-record-digest", "", "optional exact authority managed generation record digest")
	workerStorePath := flag.String("worker-store", "state/keys/go-fed-worker", "managed worker key store directory")
	workerPassphrasePath := flag.String("worker-passphrase-file", "state/keys/go-fed-worker.passphrase", "managed worker passphrase file")
	workerRecordDigest := flag.String("worker-record-digest", "", "optional exact worker managed generation record digest")
	auditPath := flag.String("audit", "state/go-fed-audit.log", "audit JSONL file")
	verifyAudit := flag.Bool("verify-audit", false, "verify audit JSONL file and exit")
	verifyReceiptPath := flag.String("verify-receipt", "", "verify one receipt record JSON file and exit")
	verifyTaskPath := flag.String("verify-task", "", "optional signed task JSON file for --verify-receipt task_digest check")
	artifactStoreGCPlan := flag.Bool("artifact-store-gc-plan", false, "print filesystem artifact mirror GC plan and exit")
	artifactStoreGCApply := flag.Bool("artifact-store-gc-apply", false, "delete orphaned filesystem artifact mirror objects and exit")
	sandboxProbe := flag.String("sandbox-probe", "", "print sandbox runtime support probe for a claim and exit")
	sandboxRequire := flag.String("sandbox-require", "", "require sandbox runtime support for a claim and exit")
	printZone := flag.Bool("print-zone", false, "print the authority Zone descriptor and exit")
	interopRequestPort := flag.String("interop-request", "", "send one FED_TASK_OPEN request to a Node federation gateway port and exit")
	verifySwarmOutputSchedulerGate := flag.Bool("verify-swarm-output-scheduler-gate", false, "verify Swarm output proof and print scheduler completion gate JSON")
	flag.Parse()

	if *printZone {
		authority, err := loadManagedIdentity(ManagedKeyConfig{StorePath: *authorityStorePath, PassphraseFile: *authorityPassphrasePath, RecordDigest: *authorityRecordDigest}, "zid")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		zone, err := zoneDescriptor(authority.PrivateKey, "zone://go-client")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := json.NewEncoder(os.Stdout).Encode(zone); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *interopRequestPort != "" {
		authority, err := loadManagedIdentity(ManagedKeyConfig{StorePath: *authorityStorePath, PassphraseFile: *authorityPassphrasePath, RecordDigest: *authorityRecordDigest}, "zid")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		requester, err := loadManagedIdentity(ManagedKeyConfig{StorePath: *workerStorePath, PassphraseFile: *workerPassphrasePath, RecordDigest: *workerRecordDigest}, "aid")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		trusted, err := loadTrustedZones(*trustPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result, err := interopRequestNode(*interopRequestPort, trusted, authority.PrivateKey, requester.PrivateKey)
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

	if *verifySwarmOutputSchedulerGate {
		store := newMemoryVerificationReplayStore()
		now := time.Now().UTC()
		if fixed := os.Getenv("ASP_VERIFY_NOW"); fixed != "" {
			parsed, err := time.Parse(time.RFC3339Nano, fixed)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			now = parsed
		}
		if err := runVerifySwarmOutputSchedulerGate(flag.Args(), store, os.Stdout, now); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *verifyAudit {
		if err := verifyAuditFile(*auditPath, *artifactStoreDir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(`{"go_audit_verify":"ok"}`)
		return
	}
	if *verifyReceiptPath != "" {
		result, err := verifyReceiptFile(*verifyReceiptPath, *artifactStoreDir, *verifyTaskPath)
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
	if *sandboxProbe != "" {
		if err := json.NewEncoder(os.Stdout).Encode(sandboxClaimProbe(*sandboxProbe)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *sandboxRequire != "" {
		probe := sandboxClaimProbe(*sandboxRequire)
		if err := json.NewEncoder(os.Stdout).Encode(probe); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if probe["supported"] != true {
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

	runtimeKeys := ManagedRuntimeConfig{
		Authority: ManagedKeyConfig{StorePath: *authorityStorePath, PassphraseFile: *authorityPassphrasePath, RecordDigest: *authorityRecordDigest},
		Worker:    ManagedKeyConfig{StorePath: *workerStorePath, PassphraseFile: *workerPassphrasePath, RecordDigest: *workerRecordDigest},
	}
	if err := serve(*listenHost, *port, *wsPort, *humanPort, *humanToken, *humanActorPolicyPath, *tlsCertPath, *tlsKeyPath, *tlsClientCAPath, *artifactStoreDir, *fixturePath, *trustPath, runtimeKeys, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type memoryVerificationReplayStore struct {
	records map[string]verifier.VerificationReplayRecord
}

func newMemoryVerificationReplayStore() *memoryVerificationReplayStore {
	return &memoryVerificationReplayStore{records: map[string]verifier.VerificationReplayRecord{}}
}

func (s *memoryVerificationReplayStore) LookupVerificationReplay(verificationID string) (verifier.VerificationReplayRecord, bool, error) {
	record, ok := s.records[verificationID]
	if !ok {
		return verifier.VerificationReplayRecord{}, false, nil
	}
	clone, err := verifier.CloneVerificationReplayRecord(record)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func (s *memoryVerificationReplayStore) PutVerificationReplayIfAbsent(record verifier.VerificationReplayRecord) (verifier.VerificationReplayRecord, bool, error) {
	if existing, ok := s.records[record.VerificationID]; ok {
		clone, err := verifier.CloneVerificationReplayRecord(existing)
		if err != nil {
			return verifier.VerificationReplayRecord{}, false, err
		}
		return clone, false, nil
	}
	stored, err := verifier.CloneVerificationReplayRecord(record)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	s.records[record.VerificationID] = stored
	clone, err := verifier.CloneVerificationReplayRecord(stored)
	if err != nil {
		return verifier.VerificationReplayRecord{}, false, err
	}
	return clone, true, nil
}

func runVerifySwarmOutputSchedulerGate(args []string, store verifier.VerificationReplayStore, out io.Writer, now time.Time) error {
	if len(args) != 1 {
		return errors.New("usage: go-fed-discovery --verify-swarm-output-scheduler-gate <bundle.json>")
	}
	completion, err := verifySwarmOutputSchedulerGateBundle(args[0], store, now)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(completion)
}

func verifySwarmOutputSchedulerGateBundle(bundlePathValue string, store verifier.VerificationReplayStore, now time.Time) (verifier.SwarmOutputSchedulerCompletion, error) {
	var zero verifier.SwarmOutputSchedulerCompletion
	baseDir := filepath.Dir(bundlePathValue)
	bundle, err := readJSONMapFile(bundlePathValue)
	if err != nil {
		return zero, err
	}
	if !hasRequiredAllowedMapFields(bundle, []string{"artifacts", "close", "executable_steps", "execution_binding", "format", "plan", "proof", "receipts", "resolved_workers", "trust_inputs", "trusted_zones"}, nil) {
		return zero, errors.New("swarm output bundle fields invalid")
	}
	if bundle["format"] != "asp-swarm-output-verification-cli/v1" {
		return zero, errors.New("swarm output bundle format invalid")
	}
	trustInputs, ok := bundle["trust_inputs"].(map[string]any)
	if !ok || !hasRequiredAllowedMapFields(trustInputs, []string{"allowlist", "trustedZones", "revocations"}, nil) {
		return zero, errors.New("swarm output trust inputs fields invalid")
	}
	readBundleJSON := func(name string, target any) (map[string]any, error) {
		path, err := bundlePath(baseDir, name, target)
		if err != nil {
			return nil, err
		}
		return readJSONMapFile(path)
	}
	proof, err := readBundleJSON("proof", bundle["proof"])
	if err != nil {
		return zero, err
	}
	planFrame, err := readBundleJSON("plan", bundle["plan"])
	if err != nil {
		return zero, err
	}
	executionBinding, err := readBundleJSON("execution_binding", bundle["execution_binding"])
	if err != nil {
		return zero, err
	}
	closeFrame, err := readBundleJSON("close", bundle["close"])
	if err != nil {
		return zero, err
	}
	stepsPath, err := bundlePath(baseDir, "executable_steps", bundle["executable_steps"])
	if err != nil {
		return zero, err
	}
	executableSteps, err := readJSONMapListFile(stepsPath)
	if err != nil {
		return zero, err
	}
	workersPath, err := bundlePath(baseDir, "resolved_workers", bundle["resolved_workers"])
	if err != nil {
		return zero, err
	}
	resolvedWorkers, err := readJSONMapListFile(workersPath)
	if err != nil {
		return zero, err
	}
	receiptsPath, err := bundlePath(baseDir, "receipts", bundle["receipts"])
	if err != nil {
		return zero, err
	}
	receiptFrames, err := readJSONMapListFile(receiptsPath)
	if err != nil {
		return zero, err
	}
	zonesPath, err := bundlePath(baseDir, "trusted_zones", bundle["trusted_zones"])
	if err != nil {
		return zero, err
	}
	zonesFile, err := readJSONMapFile(zonesPath)
	if err != nil {
		return zero, err
	}
	trustedZones, err := trustedZonesMapFromBundle(zonesFile)
	if err != nil {
		return zero, err
	}
	allowlistPath, err := bundlePath(baseDir, "allowlist", trustInputs["allowlist"])
	if err != nil {
		return zero, err
	}
	trustedVerifierZonesPath, err := bundlePath(baseDir, "trustedZones", trustInputs["trustedZones"])
	if err != nil {
		return zero, err
	}
	revocationsPath, err := bundlePath(baseDir, "revocations", trustInputs["revocations"])
	if err != nil {
		return zero, err
	}
	trust, err := verifier.LoadSwarmOutputTrustInputs(verifier.TrustInputPaths{Allowlist: allowlistPath, TrustedZones: trustedVerifierZonesPath, Revocations: revocationsPath})
	if err != nil {
		return zero, err
	}
	artifacts, ok := bundle["artifacts"].([]any)
	if !ok {
		return zero, errors.New("swarm output artifacts invalid")
	}
	artifactPaths := map[string]string{}
	seenArtifactPaths := map[string]struct{}{}
	for _, item := range artifacts {
		entry, ok := item.(map[string]any)
		if !ok || !hasRequiredAllowedMapFields(entry, []string{"path", "uri"}, nil) {
			return zero, errors.New("swarm output artifact fields invalid")
		}
		uri, ok := entry["uri"].(string)
		if !ok || uri == "" {
			return zero, errors.New("swarm output artifact uri invalid")
		}
		rawPath, ok := entry["path"].(string)
		if !ok || rawPath == "" {
			return zero, errors.New("swarm output artifact path invalid")
		}
		if _, exists := artifactPaths[uri]; exists {
			return zero, fmt.Errorf("duplicate artifact uri: %s", uri)
		}
		if _, exists := seenArtifactPaths[rawPath]; exists {
			return zero, fmt.Errorf("duplicate artifact path: %s", rawPath)
		}
		path, err := bundlePath(baseDir, "artifact", rawPath)
		if err != nil {
			return zero, err
		}
		artifactPaths[uri] = path
		seenArtifactPaths[rawPath] = struct{}{}
	}
	evidence := verifier.OutputEvidence{Proof: proof, PlanFrame: planFrame, ExecutionBinding: executionBinding, ExecutableSteps: executableSteps, ResolvedWorkers: resolvedWorkers, CloseFrame: closeFrame, ReceiptFrames: receiptFrames, TrustedZones: trustedZones, ArtifactBytes: func(artifact map[string]any) ([]byte, error) {
		artifactPath := artifactPaths[fmt.Sprint(artifact["uri"])]
		if artifactPath == "" {
			return nil, fmt.Errorf("artifact path missing: %v", artifact["uri"])
		}
		return os.ReadFile(artifactPath)
	}}
	verified, err := verifier.VerifySwarmOutput(evidence, trust, now)
	if err != nil {
		return zero, err
	}
	return verifier.ApplySwarmOutputVerification(evidence, trust, store, now, verified.CloseDigest)
}

func bundlePath(baseDir, name string, target any) (string, error) {
	text, ok := target.(string)
	if !ok || text == "" || strings.Contains(text, "\\") || filepath.IsAbs(text) {
		return "", fmt.Errorf("bundle %s path invalid", name)
	}
	for _, part := range strings.Split(text, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("bundle %s path invalid", name)
		}
	}
	return filepath.Join(baseDir, text), nil
}

func readJSONMapFile(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func readJSONMapListFile(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw []any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("JSON list entry invalid")
		}
		out = append(out, entry)
	}
	return out, nil
}

func trustedZonesMapFromBundle(value map[string]any) (map[string]map[string]any, error) {
	items, ok := value["zones"].([]any)
	if !ok {
		return nil, errors.New("trusted zones invalid")
	}
	out := map[string]map[string]any{}
	for _, item := range items {
		zone, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("trusted zone entry invalid")
		}
		out[fmt.Sprint(zone["zid"])] = zone
	}
	return out, nil
}

func serve(listenHost, port, wsPort, humanPort, humanToken, humanActorPolicyPath, tlsCertPath, tlsKeyPath, tlsClientCAPath, artifactStoreDir, fixturePath, trustPath string, runtimeKeys ManagedRuntimeConfig, auditPath string) error {
	fixture, err := loadManagedFixture(fixturePath, runtimeKeys)
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
	listener, transport, err := listenFederation(listenHost, port, tlsCertPath, tlsKeyPath, tlsClientCAPath)
	if err != nil {
		return err
	}
	listenPort := port
	if addr, ok := listener.Addr().(*net.TCPAddr); ok {
		listenPort = strconv.Itoa(addr.Port)
	}
	fixture.ListenHost = listenHost
	fixture.ListenPort = listenPort
	fixture.Transport = transport
	fixture.PublicTransport = isPublicListenHost(listenHost)
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
		go serveHumanGateway(humanListener, auditPath, fixture, humanToken, listenHost)
	}
	if wsPort != "" || humanPort != "" {
		status := map[string]any{"go_fed_discovery": "listening", "listen_host": listenHost, "port": listenPort, "public_transport": fixture.PublicTransport, "transport": transport}
		if wsPort != "" {
			status["ws_port"] = wsPort
		}
		if humanPort != "" {
			status["human_port"] = humanPort
		}
		data, _ := json.Marshal(status)
		fmt.Println(string(data))
	} else {
		status := map[string]any{"go_fed_discovery": "listening", "listen_host": listenHost, "port": listenPort, "public_transport": fixture.PublicTransport, "transport": transport}
		data, _ := json.Marshal(status)
		fmt.Println(string(data))
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handle(conn, fixture, trusted)
	}
}

func listenFederation(host, port, tlsCertPath, tlsKeyPath, tlsClientCAPath string) (net.Listener, string, error) {
	if (tlsCertPath == "") != (tlsKeyPath == "") {
		return nil, "", errors.New("both --tls-cert and --tls-key are required")
	}
	if tlsClientCAPath != "" && tlsCertPath == "" {
		return nil, "", errors.New("--tls-client-ca requires --tls-cert and --tls-key")
	}
	addr := net.JoinHostPort(host, port)
	if tlsCertPath == "" {
		listener, err := net.Listen("tcp", addr)
		return listener, "fed+tcp", err
	}
	cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
	if err != nil {
		return nil, "", err
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	transport := "fed+tls"
	if tlsClientCAPath != "" {
		caPEM, err := os.ReadFile(tlsClientCAPath)
		if err != nil {
			return nil, "", err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, "", errors.New("tls client CA file has no certificates")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
		transport = "fed+mtls"
	}
	listener, err := tls.Listen("tcp", addr, config)
	return listener, transport, err
}

func isPublicListenHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback() && !ip.IsUnspecified()
}

func handle(conn net.Conn, fixture Fixture, trusted map[string]map[string]any) {
	defer conn.Close()
	session := &Session{}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		certs := tlsConn.ConnectionState().PeerCertificates
		session.TransportPeerCert = len(certs) > 0
		session.TransportPeerZoneIDs = certificateZoneIDs(certs)
	}
	scanner := bufio.NewScanner(conn)
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
		matches := []map[string]any{}
		capability := fmt.Sprint(frame["capability"])
		intent := optionalString(frame["intent"])
		for i := range fixture.Workers {
			queryScope, _ := frame["scope"].(map[string]any)
			if match := fixture.queryMatch(&fixture.Workers[i], capability, intent, queryScope); match != nil {
				matches = append(matches, match)
			}
		}
		sort.Slice(matches, func(i, j int) bool {
			left := intFromMap(matches[i]["ranking"], "score")
			right := intFromMap(matches[j]["ranking"], "score")
			if left != right {
				return left > right
			}
			return optionalString(matches[i]["worker"].(map[string]any)["alias"]) < optionalString(matches[j]["worker"].(map[string]any)["alias"])
		})
		items := make([]any, 0, len(matches))
		for _, match := range matches {
			items = append(items, match)
		}
		send(map[string]any{
			"type":       "FED_QUERY_RESULT",
			"zone":       fixture.Authority,
			"capability": frame["capability"],
			"matches":    items,
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
	case "FED_ARTIFACT_READ":
		result, err := fixture.artifactReadProof(fmt.Sprint(frame["task_id"]), fmt.Sprint(frame["uri"]))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		send(result)
		send(map[string]any{"type": "FED_ARTIFACT_CLOSE", "task_id": frame["task_id"], "uri": frame["uri"]})
	case "FED_TASK_OPEN":
		worker, task, err := fixture.verifyTaskOpen(frame)
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, nil, "", nil, true, nil, nil); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_SWARM_OPEN":
		if err := fixture.executeSwarm(send, origin, frame); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_SWARM_SCHEDULE":
		if err := fixture.executeScheduledSwarm(send, origin, frame); err != nil {
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
		if err := validateTaskID(taskID); err != nil {
			send(taskErrorFrame(err))
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
		if err := validateTaskID(taskID); err != nil {
			send(taskErrorFrame(err))
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
		if err := validateTaskID(taskID); err != nil {
			send(taskErrorFrame(err))
			return false
		}
		if err := fixture.drainQueueItem(send, taskID, fmt.Sprint(frame["lease_id"])); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_RESUME":
		worker, task, err := fixture.verifyTaskOpen(taskOpenFrameForVerification(frame))
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
		if err := fixture.executeTask(send, origin, worker, task, checkpointID, optionalString(parentCheckpoint["state_digest"]), nil, true, nil, nil); err != nil {
			send(taskErrorFrame(err))
			return false
		}
	case "FED_TASK_RETRY":
		worker, task, err := fixture.verifyTaskOpen(taskOpenFrameForVerification(frame))
		if err != nil {
			send(taskErrorFrame(err))
			return false
		}
		retryOf := fmt.Sprint(frame["retry_of"])
		if retryOf == "" || retryOf == "<nil>" {
			send(taskErrorFrame(errors.New("retry_of missing")))
			return false
		}
		if err := fixture.executeTask(send, origin, worker, task, nil, "", retryOf, true, nil, nil); err != nil {
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
