package main

import (
	"context"
	"crypto/ed25519"
	"regexp"
	"sync"
)

type Fixture struct {
	Authority           map[string]any      `json:"authority"`
	WorkerProfile       WorkerProfile       `json:"worker_profile"`
	WorkerProfiles      []WorkerProfile     `json:"worker_profiles"`
	Workers             []Worker            `json:"-"`
	Credential          map[string]any      `json:"credential"`
	Revocations         []any               `json:"revocations"`
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
	ListenHost          string              `json:"-"`
	ListenPort          string              `json:"-"`
	Transport           string              `json:"-"`
	PublicTransport     bool                `json:"-"`
}

const requesterRegistryPath = "state/go-fed-discovery-requester-registry.json"
const requesterRebindingHistoryPath = "state/go-fed-discovery-requester-rebindings.json"
const base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const credentialValidUntilPattern = `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$`

var ed25519MultikeyPrefix = []byte{0xed, 0x01}
var credentialValidUntilRegexp = regexp.MustCompile(credentialValidUntilPattern)

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
	ID                   string
	Challenge            string
	PeerZID              string
	Authenticated        bool
	TransportPeerCert    bool
	TransportPeerZoneIDs map[string]bool
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

type sandboxClaimError struct {
	claim string
	probe map[string]any
}

func (e sandboxClaimError) Error() string {
	return "unsupported sandbox claim: " + e.claim
}

func taskErrorFrame(err error) map[string]any {
	frame := map[string]any{"type": "FED_TASK_ERROR", "error": err.Error()}
	if coded, ok := err.(codedError); ok {
		frame["code"] = coded.Code()
	}
	return frame
}
