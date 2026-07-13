export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type AlertStatus = "unconfirmed" | "confirmed" | "ignored";

export interface AlertRecord {
  id: number;
  timestamp: string;
  severity: Severity;
  ruleId: string;
  ruleName: string;
  source: string;
  destination: string;
  protocol: string;
  description: string;
  evidence: string;
  status: AlertStatus;
  packetIds?: number[];
}

export interface PacketRecord {
  id: number;
  sequence?: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  flags: string;
  summary: string;
  details?: Record<string, unknown>;
}

export type CaptureState = "stopped" | "running" | "paused" | "stopping" | "error";

export interface CaptureStatus {
  state: CaptureState;
  interface: string;
  filterExpression: string;
  savePackets: boolean;
  detectionEnabled: boolean;
  packetTotal: number;
  alertTotal: number;
  skippedTotal: number;
  savedPacketTotal: number;
  savedAlertTotal: number;
  packetsPerSecond: number;
  error: string;
  nextSequence: number;
}

export interface CaptureStartOptions {
  interface: string | null;
  filterExpression: string;
  savePackets: boolean;
  detectionEnabled: boolean;
  alertCooldownSeconds: number;
}

export interface PcapImportStatus {
  state: "idle" | "importing" | "completed" | "error";
  filename: string;
  packetTotal: number;
  alertTotal: number;
  skippedTotal: number;
  savedPacketTotal: number;
  savedAlertTotal: number;
  error: string;
}

export type ThemePreference = "system" | "light" | "dark";

export interface LlmSettings {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export interface SecurityCheck {
  identifier: string;
  title: string;
  state: "pass" | "warning" | "fail" | "unavailable";
  value: string;
  detail: string;
  recommendation: string;
}

export interface ProcessRecord {
  pid: number;
  name: string;
  memory: string;
  path: string;
}

export interface IntegrityStatus {
  available: boolean;
  paths: string[];
  fileCount: number;
  createdAt: string;
}

export interface IntegrityResult {
  paths: string[];
  fileCount: number;
  skipped: { path: string; reason: string }[];
  createdAt?: string;
  scannedAt?: string;
  added?: string[];
  removed?: string[];
  modified?: string[];
}

export interface HostRecord {
  ip: string;
  name: string;
  role: string;
  risk: number;
  importance: number;
  packets: number;
  alerts: number;
  lastSeen: string;
  incomingPackets?: number;
  outgoingPackets?: number;
  riskReasons?: string[];
  protocols?: { name: string; value: number }[];
}

export interface TrendPoint {
  time: string;
  alerts: number;
  packets: number;
  bucket?: string;
  spike?: boolean;
}

export interface DashboardSnapshot {
  capture: CaptureStatus;
  statistics: {
    packetTotal: number;
    alertTotal: number;
    openAlerts: number;
    highPriorityAlerts: number;
    highRiskHosts: number;
    lastHourPackets: number;
  };
  trend: TrendPoint[];
  severityDistribution: { name: string; value: number; color: string }[];
  highRiskHosts: HostRecord[];
  recentAlerts: AlertRecord[];
}

export interface HostConnection {
  peer: string;
  direction: "Inbound" | "Outbound";
  protocol: string;
  port: number | null;
  packets: number;
  lastSeen: string;
}

export interface HostTimelineEvent {
  timestamp: string;
  type: "Packet" | "Alert";
  direction: "Inbound" | "Outbound";
  peer: string;
  summary: string;
  severity: string;
}

export interface HostProfile {
  host: HostRecord;
  protocols: { name: string; value: number }[];
  ports: { port: number; count: number }[];
  connections: HostConnection[];
  alerts: AlertRecord[];
  timeline: HostTimelineEvent[];
}
