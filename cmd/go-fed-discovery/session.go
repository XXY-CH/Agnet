package main

import (
	"agnet/verifier"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

func handleHello(send sendFunc, frame map[string]any, fixture Fixture, trusted map[string]map[string]any, session *Session) error {
	origin, ok := frame["origin_zone"].(map[string]any)
	if !ok {
		return errors.New("missing origin_zone")
	}
	if err := verifyTrustedZone(origin, trusted); err != nil {
		return err
	}
	if session.TransportPeerCert && !session.TransportPeerZoneIDs[fmt.Sprint(origin["zid"])] {
		return errors.New("mTLS client certificate zone mismatch")
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

func certificateZoneIDs(certs []*x509.Certificate) map[string]bool {
	zones := map[string]bool{}
	if len(certs) == 0 {
		return zones
	}
	for _, uri := range certs[0].URIs {
		zones[uri.String()] = true
	}
	return zones
}

func sessionAuthBody(sessionID, challenge, peerZID, remoteZID string) map[string]any {
	return map[string]any{"session_id": sessionID, "challenge": challenge, "peer_zid": peerZID, "remote_zid": remoteZID}
}

func interopRequestNode(port string, trusted map[string]map[string]any, zoneKey, requesterKey ed25519.PrivateKey) (map[string]any, error) {
	origin, err := zoneDescriptor(zoneKey, "zone://go-client")
	if err != nil {
		return nil, err
	}
	requester, err := agentDescriptor(requesterKey, "agent://go-client/requester")
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	decoder := json.NewDecoder(conn)
	if err := json.NewEncoder(conn).Encode(map[string]any{"type": "HELLO", "origin_zone": origin}); err != nil {
		return nil, err
	}
	events := []any{}
	var receipt map[string]any
	var signedTask map[string]any
	for {
		var frame map[string]any
		if err := decoder.Decode(&frame); err != nil {
			return nil, err
		}
		switch frame["type"] {
		case "HELLO":
			remote, ok := frame["zone"].(map[string]any)
			if !ok {
				return nil, errors.New("remote zone missing")
			}
			if err := verifyTrustedZone(remote, trusted); err != nil {
				return nil, err
			}
			body := sessionAuthBody(fmt.Sprint(frame["session_id"]), fmt.Sprint(frame["challenge"]), fmt.Sprint(origin["zid"]), fmt.Sprint(remote["zid"]))
			if err := json.NewEncoder(conn).Encode(map[string]any{"type": "AUTH", "origin_zone": origin, "auth": signBodyWithKey(zoneKey, body, "auth_signature")}); err != nil {
				return nil, err
			}
		case "AUTH_OK":
			task := map[string]any{
				"task_id": "go_node_interop_task",
				"from":    requester["aid"],
				"to":      "agent://zone-b/summarizer",
				"intent":  "Summarize through Node from Go.",
				"scope":   map[string]any{"network": false},
				"budget":  map[string]any{"time_seconds": float64(30)},
			}
			signedTask = signBody(requesterKey, task)
			if err := json.NewEncoder(conn).Encode(map[string]any{"type": "FED_TASK_OPEN", "origin_zone": origin, "requester": requester, "requester_zone_binding": signBodyWithKey(zoneKey, map[string]any{"zone": origin["zid"], "alias": requester["alias"], "aid": requester["aid"]}, "signature"), "task": signedTask}); err != nil {
				return nil, err
			}
		case "FED_TASK_EVENT":
			events = append(events, frame["event"])
		case "FED_RECEIPT":
			if err := verifyInteropReceipt(frame, trusted, signedTask); err != nil {
				return nil, err
			}
			receipt, _ = frame["receipt"].(map[string]any)
		case "FED_TASK_CLOSE":
			if receipt == nil {
				return nil, errors.New("remote receipt missing")
			}
			return map[string]any{"origin_zone": origin["zid"], "events": events, "receipt": receipt}, nil
		case "FED_TASK_ERROR":
			return nil, errors.New(fmt.Sprint(frame["error"]))
		}
	}
}

func verifyInteropReceipt(frame map[string]any, trusted map[string]map[string]any, signedTasks ...map[string]any) error {
	return verifier.VerifyFederatedReceipt(frame, trusted, signedTasks...)
}
