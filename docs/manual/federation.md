# Federation gateway

Agnet has two federation gateway surfaces: the compact Node prototype in `federation-gateway.mjs` and the Go gateway in `cmd/go-fed-discovery/main.go`. Both speak newline-delimited JSON frames and verify trusted Zones before accepting federation work.

## Go gateway quick setup

```bash
go run ./cmd/go-fed-discovery   --listen-host 127.0.0.1   --port 9090   --ws-port 9091   --human-port 8080
```

The default federation transport is local TCP. Use `--listen-host 0.0.0.0` or an explicit non-loopback host only when producing public-listen proof evidence.

## Trusted Zones

Trusted Zone files are either:

```json
{ "zones": [{ "zid": "zid:ed25519:...", "name": "zone://...", "public_key_spki": "...", "signature": "..." }] }
```

or a raw descriptor array. Missing Zone lists fail closed before entries are read. Federation verification matches Zone IDs and public keys, not names alone.

## TLS and mTLS

The Go federation listener accepts TLS and optional mTLS:

```bash
go run ./cmd/go-fed-discovery   --listen-host 0.0.0.0   --port 9090   --tls-cert path/to/server.crt   --tls-key path/to/server.key   --tls-client-ca path/to/client-ca.crt
```

With mTLS, the client certificate Zone must match the claimed federation Zone. A mismatch emits `FED_TASK_ERROR` and does not continue execution.

## Common gateway flags

| Flag | Purpose |
| --- | --- |
| `--listen-host` | Main TCP federation listen host, default `127.0.0.1`. |
| `--port` | Main TCP federation port, default `9090`. |
| `--ws-port` | Optional WebSocket listener. |
| `--human-port` | Optional Human Gateway HTTP UI/API. |
| `--human-token` | Optional bearer token for Human Gateway write actions. |
| `--human-actor-policy` | Optional local actor policy JSON file. |
| `--tls-cert` / `--tls-key` | TLS certificate and private key. |
| `--tls-client-ca` | mTLS client CA. |
| `--artifact-store` | Filesystem artifact mirror directory. |
| `--fixture` | Signed descriptor fixture path. |
| `--trusted` | Trusted origin Zones file. |
| `--authority-key` / `--worker-key` | Seed key files. |
| `--audit` | Audit JSONL file. |

## Cross-zone usage

v14.3 adds local-first Zone trust delegation. A trusted authority Zone signs a delegation for a delegate Zone, `verifyZoneTrustDelegation` checks the signature and capability array, and discovery evidence can include that record in `zone_trust_chain`. Direct local trust remains represented as `zone_trust_chain: []`.

This is signed local delegation evidence only. It is not a global PKI, DID universal resolver, network revocation sync, or cross-zone legal liability system.

## Public-listen proof

Run the local public-listen proof:

```bash
bash scripts/public-node-proof.sh
```

For hosted observation attempts, set an explicit global literal IP and keepalive window:

```bash
AGNET_PUBLIC_LISTEN_HOST=<global-ip> AGNET_PUBLIC_PROOF_KEEPALIVE_MS=600000 bash scripts/public-node-proof.sh
```

`proof-bundle` owns the reachability label. It reports `local-interface` by default, `container-observer` for trusted container evidence, and `external-host` only for trusted external-host evidence plus a globally routable literal-IP `listen_host`.
