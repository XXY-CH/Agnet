package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	authorityKeyPath := flag.String("authority-key", "state/keys/go-fed-authority.seed", "authority seed key file")
	workerKeyPath := flag.String("worker-key", "state/keys/go-fed-worker.seed", "worker seed key file")
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
	flag.Parse()

	if *printZone {
		authorityKey, err := loadPrivateKey(*authorityKeyPath, "authority")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		zone, err := zoneDescriptor(authorityKey, "zone://go-client")
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
		authorityKey, err := loadPrivateKey(*authorityKeyPath, "authority")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		requesterKey, err := loadPrivateKey(*workerKeyPath, "requester")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		trusted, err := loadTrustedZones(*trustPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		result, err := interopRequestNode(*interopRequestPort, trusted, authorityKey, requesterKey)
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

	if err := serve(*listenHost, *port, *wsPort, *humanPort, *humanToken, *humanActorPolicyPath, *tlsCertPath, *tlsKeyPath, *tlsClientCAPath, *artifactStoreDir, *fixturePath, *trustPath, *authorityKeyPath, *workerKeyPath, *auditPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(listenHost, port, wsPort, humanPort, humanToken, humanActorPolicyPath, tlsCertPath, tlsKeyPath, tlsClientCAPath, artifactStoreDir, fixturePath, trustPath, authorityKeyPath, workerKeyPath, auditPath string) error {
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
