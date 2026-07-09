package main

import (
	"fmt"
	"html"
	"net/url"
	"strconv"
	"strings"
)

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
