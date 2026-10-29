import { authFetch } from "@/lib/auth";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function handle<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof body?.detail === "string" ? body.detail : `Request failed (${response.status})`;
    throw new ApiError(response.status, detail);
  }
  return body as T;
}

export async function apiGet<T>(path: string): Promise<T> {
  return handle<T>(await authFetch(`${API_URL}${path}`, { cache: "no-store" }));
}

export async function apiSend<T>(path: string, method: "POST" | "PATCH", data: unknown): Promise<T> {
  return handle<T>(
    await authFetch(`${API_URL}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    })
  );
}

export async function apiDelete<T>(path: string): Promise<T> {
  return handle<T>(await authFetch(`${API_URL}${path}`, { method: "DELETE" }));
}

export async function apiUpload<T>(path: string, files: File[]): Promise<T> {
  const form = new FormData();
  files.forEach((f) => form.append("files", f));
  return handle<T>(await authFetch(`${API_URL}${path}`, { method: "POST", body: form }));
}

export async function downloadFile(path: string, name: string) {
  const response = await authFetch(`${API_URL}/api/files/download?path=${encodeURIComponent(path)}`);
  if (!response.ok) throw new ApiError(response.status, "Download failed");
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

export type TrustView = {
  mean: number;
  lower: number;
  std: number;
  evidence: number;
  tier: "trusted" | "standard" | "probation" | "restricted";
  positive: number;
  negative: number;
};

export type TrustEvent = {
  id: number;
  pos_delta: number;
  neg_delta: number;
  reason: string;
  source: string;
  mean_after: number;
  lower_after: number;
  created_at: string;
};

export type ContentFinding = { severity: string; finding: string };

export type Decision = "ALLOW" | "REVIEW" | "DENY";

export type SecurityEvent = {
  id: number;
  run_id: string | null;
  agent_id: number;
  agent_name: string;
  tool_name: string;
  action: string;
  arguments: Record<string, unknown> | null;
  decision: Decision;
  risk_score: number;
  rule: string | null;
  reasons: string[];
  factors: Record<string, number>;
  trust_before: number | null;
  tainted: boolean | null;
  destination?: string | null;
  content_findings?: ContentFinding[];
  request_risk?: number | null;
  created_at: string;
};

export type Agent = {
  id: number;
  name: string;
  role: string;
  description: string | null;
  allowed_tools: string[];
  trust_score: number;
  trust: TrustView;
  is_active: boolean;
  quarantined_until: string | null;
  decisions: Record<Decision, number>;
};

export type TraceStep = {
  step: number;
  tool: string;
  arguments: Record<string, unknown>;
  decision: Decision;
  risk_score: number;
  rule: string | null;
  reasons: string[];
  factors: Record<string, number>;
  tainted: boolean;
  destination?: string | null;
  content_findings?: ContentFinding[];
  tool_status: string | null;
  tool_summary?: string;
};

export type FileInfo = { name: string; path: string; size: number };

export type Attachment = FileInfo & { scan?: { score: number; findings: ContentFinding[] } };

export type ChatMessage = {
  id: number;
  role: "user" | "assistant";
  content: string;
  agent_id: number | null;
  run_id: string | null;
  attachments: Attachment[];
  meta: {
    type?: string;
    agent_name?: string;
    routing?: { method: string; reason: string } | null;
    trace?: TraceStep[];
    files_created?: FileInfo[];
    approved_files?: FileInfo[];
    approval_id?: number | null;
    pending_tool?: string | null;
    resumed_approval_id?: number;
    handoff_to?: string | null;
    data_level?: number;
    request_scan?: { score: number; findings: ContentFinding[] };
    trust?: { agent_before: TrustView; agent_after: TrustView; user_after: TrustView };
  };
  created_at: string;
};

export type AgentRun = {
  id: string;
  agent_id: number;
  agent_name: string;
  user_email: string | null;
  prompt: string;
  status: string;
  final_output: string | null;
  steps: number;
  created_at: string;
  events: SecurityEvent[];
};
