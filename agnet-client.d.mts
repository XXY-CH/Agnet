export interface ToolCorrelation {
  workspace_id: string;
  conversation_id: string;
  session_id: string;
  run_id: string;
  tool_call_id: string;
  task_id: string;
  payload_digest: string;
  operation_digest: string;
  attempt?: number;
}

export interface ProductIntent {
  intentId: string;
  workspaceId: string;
  conversationId: string;
  text: string;
}

export interface TaskScope {
  readonly network?: boolean;
  readonly write?: readonly string[];
  readonly data_domains?: readonly string[];
  readonly expires_at?: string;
}

export interface TaskView {
  task_id: string;
  status: "queued" | "claimed" | "running" | "completing" | "cancelling" | "failing" | "completed" | "failed" | "cancelled";
  worker?: string;
  to?: string;
  intent?: string;
  scope?: TaskScope;
  correlation?: ToolCorrelation;
  approval?: Record<string, unknown>;
  artifact_refs?: string[];
  receipt_digest?: string;
  retry_of?: string;
  retry_attempt?: number;
  error?: string;
}

export interface CommittedReceipt {
  committed: true;
  task_id: string;
  status: "completed" | "failed" | "cancelled";
  receipt_digest: string;
  audit_hash: string;
  zone: Record<string, unknown>;
  worker: Record<string, unknown>;
  zone_binding: Record<string, unknown>;
  signed_task: Record<string, unknown>;
  receipt: Record<string, unknown> & { artifact_refs?: string[]; artifact_manifests?: Array<Record<string, unknown>> };
}

export interface VerifiedReceipt extends CommittedReceipt {
  verified: true;
  verification: {
    mode: "local";
    receipt_digest: string;
    artifact_count: number;
  };
}

export interface AgnetTaskEvent {
  cursor: number;
  type: string;
  verified: boolean;
  payload: Record<string, unknown>;
}

export interface AgnetClientOptions {
  baseURL: string;
  token?: string;
  trustedZones?: ReadonlyArray<Record<string, unknown>> | ReadonlyMap<string, Record<string, unknown>>;
  maxArtifactBytes?: number;
  fetch?: typeof globalThis.fetch;
  pollIntervalMs?: number;
  allowInsecureRemote?: boolean;
}

export interface CreateTaskInput {
  taskId: string;
  to: string;
  intent: string;
  scope: TaskScope;
  payload: Record<string, unknown>;
  correlation: ToolCorrelation | {
    workspaceId: string;
    conversationId: string;
    sessionId: string;
    runId: string;
    toolCallId: string;
    taskId: string;
    payloadDigest: string;
    operationDigest: string;
  };
  budget?: Record<string, unknown>;
  artifactRef?: string;
  approvalExpiresAt?: string;
}

export interface SubscriptionOptions {
  after?: string | number;
  signal?: AbortSignal;
  onError?: (error: unknown) => void;
}

export class AgnetAPIError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  constructor(message: string, options?: { status?: number; code?: string; details?: unknown; cause?: unknown });
}

export function agnetTaskId(sessionId: string, toolCallId: string): string;
export function createToolCorrelation(input: {
  workspaceId: string;
  conversationId: string;
  sessionId: string;
  runId: string;
  toolCallId: string;
  taskId?: string;
  payloadDigest: string;
  operationDigest: string;
}): ToolCorrelation;

export class AgnetClient {
  constructor(options: AgnetClientOptions);
  createIntent(input: { workspaceId: string; conversationId: string; text: string }): ProductIntent;
  handshake(input: { packageVersion: string; productApi: "agnet.product-api/v1"; capabilities: readonly string[] }): Promise<{ packageName: "agnet"; packageVersion: string; productApi: "agnet.product-api/v1"; capabilities: readonly string[] }>;
  createTask(input: CreateTaskInput): Promise<TaskView>;
  execute(taskId: string, correlation: ToolCorrelation): Promise<TaskView>;
  cancel(taskId: string, reason: string | undefined, correlation: ToolCorrelation): Promise<TaskView>;
  retry(taskId: string, input: { taskId: string }): Promise<TaskView>;
  approve(input: { taskId: string; actor?: string }): Promise<Record<string, unknown>>;
  deny(input: { taskId: string; actor?: string }): Promise<Record<string, unknown>>;
  getTask(taskId: string): Promise<TaskView>;
  getReceipt(taskId: string): Promise<CommittedReceipt>;
  replay(taskId: string, after?: number): Promise<{ events: readonly AgnetTaskEvent[]; nextCursor: number }>;
  verifyReceipt(receipt: CommittedReceipt): Promise<VerifiedReceipt>;
  getArtifact(taskId: string, reference: string | { uri: string }, options?: { signal?: AbortSignal }): Promise<ReadableStream<Uint8Array>>;
  subscribe(taskId: string, listener: (event: AgnetTaskEvent) => void, options?: SubscriptionOptions): () => void;
}
