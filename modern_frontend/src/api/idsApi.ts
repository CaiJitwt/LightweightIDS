import type {
  AlertRecord,
  AlertStatus,
  AssetRecord,
  CaptureStartOptions,
  CaptureStatus,
  DashboardSnapshot,
  EventTimelineRecord,
  HostProfile,
  HostRecord,
  IntegrityResult,
  IntegrityStatus,
  InvestigationRecord,
  PacketRecord,
  PcapImportStatus,
  ProcessRecord,
  SecurityCheck,
  SecurityEventRecord,
  SecurityEventStatus,
  SystemHealthSnapshot,
  TopologySnapshot,
  RuleRecord,
  RuntimeSettings,
  RuntimeSettingsUpdate,
} from "../types";
import { translations } from "../i18n/translations";
import type { PersonalizationState } from "../data/personalizationStore";

// Sentinel "all" values across every locale — used to decide whether to omit
// filter params from API requests (the backend only accepts concrete values).
const ALL_SEVERITY_SENTINELS: Set<string> = new Set(
  Object.values(translations).map((t) => t["common.allSeverities"]),
);
const ALL_CHANNEL_SENTINELS: Set<string> = new Set(
  Object.values(translations).map((t) => t["common.allChannels"]),
);

const apiBase = import.meta.env.VITE_IDS_API_BASE ?? "";

export class LocalApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "LocalApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  const body = await response.json().catch(() => ({})) as T & { error?: string };
  if (!response.ok) throw new LocalApiError(body.error ?? `Local API request failed (${response.status}).`, response.status);
  return body;
}

async function uploadPcap(file: File): Promise<PcapImportStatus> {
  const response = await fetch(`${apiBase}/api/pcap/import`, {
    method: "POST",
    headers: { "Content-Type": file.type || "application/octet-stream", "X-Filename": file.name },
    body: file,
  });
  const body = await response.json().catch(() => ({})) as PcapImportStatus & { error?: string };
  if (!response.ok) throw new LocalApiError(body.error ?? `PCAP import failed (${response.status}).`, response.status);
  return body;
}

async function uploadPersonalizationImage(kind: "background" | "petImage", file: Blob, filename: string) {
  const response = await fetch(`${apiBase}/api/personalization/images/${kind}`, {
    method: "POST",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      "X-Filename": filename,
    },
    body: file,
  });
  const body = await response.json().catch(() => ({})) as { url?: string; error?: string };
  if (!response.ok || !body.url) {
    throw new LocalApiError(body.error ?? `Personalization image upload failed (${response.status}).`, response.status);
  }
  return { url: body.url };
}

export const idsApi = {
  health: () => request<{ ok: boolean }>("/api/health"),
  systemTheme: () => request<{ dark: boolean }>("/api/system/theme"),
  interfaces: () => request<{ interfaces: string[] }>("/api/capture/interfaces"),
  status: () => request<CaptureStatus>("/api/capture/status"),
  pcapStatus: () => request<PcapImportStatus>("/api/pcap/status"),
  importPcap: uploadPcap,
  start: (options: CaptureStartOptions) => request<CaptureStatus>("/api/capture/start", { method: "POST", body: JSON.stringify(options) }),
  pause: () => request<CaptureStatus>("/api/capture/pause", { method: "POST", body: "{}" }),
  resume: () => request<CaptureStatus>("/api/capture/resume", { method: "POST", body: "{}" }),
  stop: () => request<CaptureStatus>("/api/capture/stop", { method: "POST", body: "{}" }),
  validateFilter: (filterExpression: string) => request<{ expression: string; bpf: string }>("/api/capture/validate-filter", { method: "POST", body: JSON.stringify({ filterExpression }) }),
  packets: (after: number) => request<{ records: PacketRecord[]; nextSequence: number }>(`/api/packets?after=${after}&limit=250`),
  dashboard: () => request<DashboardSnapshot>("/api/dashboard"),
  timeline: () => request<{ records: EventTimelineRecord[] }>("/api/timeline?limit=500"),
  topology: () => request<TopologySnapshot>("/api/topology"),
  resetStatistics: () => request<{ reset: boolean; dashboard: DashboardSnapshot }>("/api/statistics/reset", { method: "POST", body: "{}" }),
  alerts: (filters: { query?: string; severity?: string; limit?: number } = {}) => {
    const params = new URLSearchParams();
    if (filters.query) params.set("query", filters.query);
    if (filters.severity && !ALL_SEVERITY_SENTINELS.has(filters.severity)) params.set("severity", filters.severity);
    params.set("limit", String(filters.limit ?? 500));
    return request<{ records: AlertRecord[] }>(`/api/alerts?${params.toString()}`);
  },
  alertPackets: (alertId: number) => request<{ records: PacketRecord[] }>(`/api/alerts/${alertId}/packets`),
  updateAlertStatus: (alertId: number, status: AlertStatus) => request<{ record: AlertRecord }>(`/api/alerts/${alertId}/status`, { method: "POST", body: JSON.stringify({ status }) }),
  hosts: (query = "") => request<{ records: HostRecord[] }>(`/api/hosts?query=${encodeURIComponent(query)}&limit=500`),
  host: (ip: string) => request<HostProfile>(`/api/hosts/${encodeURIComponent(ip)}`),
  posture: () => request<{ checks: SecurityCheck[] }>("/api/security/posture"),
  processes: () => request<{ processes: ProcessRecord[] }>("/api/security/processes?limit=100"),
  systemHealth: () => request<SystemHealthSnapshot>("/api/system/health"),
  integrityStatus: () => request<IntegrityStatus>("/api/security/integrity/status"),
  createIntegrityBaseline: (paths: string[]) => request<IntegrityResult>("/api/security/integrity/baseline", { method: "POST", body: JSON.stringify({ paths }) }),
  scanIntegrity: () => request<IntegrityResult>("/api/security/integrity/scan", { method: "POST", body: "{}" }),
  securityEvents: (filters: { query?: string; severity?: string; channel?: string; eventId?: string; limit?: number } = {}) => {
    const params = new URLSearchParams();
    if (filters.query) params.set("query", filters.query);
    if (filters.severity && !ALL_SEVERITY_SENTINELS.has(filters.severity)) params.set("severity", filters.severity);
    if (filters.channel && !ALL_CHANNEL_SENTINELS.has(filters.channel)) params.set("channel", filters.channel);
    if (filters.eventId) params.set("eventId", filters.eventId);
    params.set("limit", String(filters.limit ?? 500));
    return request<{ records: SecurityEventRecord[]; total: number; status: SecurityEventStatus }>(`/api/security/events?${params.toString()}`);
  },
  securityEventStatus: () => request<SecurityEventStatus>("/api/security/events/status"),
  startSecurityEvents: () => request<SecurityEventStatus>("/api/security/events/start", { method: "POST", body: "{}" }),
  stopSecurityEvents: () => request<SecurityEventStatus>("/api/security/events/stop", { method: "POST", body: "{}" }),
  refreshSecurityEvents: () => request<SecurityEventStatus>("/api/security/events/refresh", { method: "POST", body: "{}" }),
  alertSecurityEvent: (alertId: number) => request<{ record: SecurityEventRecord | null }>(`/api/alerts/${alertId}/security-event`),
  settings: () => request<RuntimeSettings>("/api/settings"),
  saveSettings: (settings: RuntimeSettingsUpdate) => request<RuntimeSettings>("/api/settings", { method: "POST", body: JSON.stringify(settings) }),
  personalization: () => request<{ state: PersonalizationState; persisted: boolean }>("/api/personalization"),
  savePersonalization: (state: PersonalizationState) => request<{ state: PersonalizationState; persisted: boolean }>("/api/personalization", { method: "POST", body: JSON.stringify(state) }),
  uploadPersonalizationImage,
  rules: () => request<{ records: RuleRecord[] }>("/api/rules"),
  updateRule: (id: string, update: Partial<Pick<RuleRecord, "enabled" | "threshold" | "timeWindow">>) => request<{ record: RuleRecord }>(`/api/rules/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify(update) }),
  assets: () => request<{ records: AssetRecord[] }>("/api/assets"),
  saveAsset: (asset: { ip: string; displayName: string; role: string; importance: number; notes: string }) => request<{ record: AssetRecord }>("/api/assets", { method: "POST", body: JSON.stringify(asset) }),
  updateAsset: (ip: string, asset: { displayName: string; role: string; importance: number; notes: string }) => request<{ record: AssetRecord }>(`/api/assets/${encodeURIComponent(ip)}`, { method: "PUT", body: JSON.stringify(asset) }),
  deleteAsset: (ip: string) => request<{ deleted: boolean }>(`/api/assets/${encodeURIComponent(ip)}`, { method: "DELETE" }),
  investigations: () => request<{ records: InvestigationRecord[] }>("/api/investigations"),
  createInvestigation: (record: { title: string; status: string; priority: string; hostIp: string; summary: string; notes: string }) => request<{ record: InvestigationRecord }>("/api/investigations", { method: "POST", body: JSON.stringify(record) }),
  updateInvestigation: (id: number, record: { title: string; status: string; priority: string; hostIp: string; summary: string; notes: string }) => request<{ record: InvestigationRecord }>(`/api/investigations/${id}`, { method: "PUT", body: JSON.stringify(record) }),
  deleteInvestigation: (id: number) => request<{ deleted: boolean }>(`/api/investigations/${id}`, { method: "DELETE" }),
};
