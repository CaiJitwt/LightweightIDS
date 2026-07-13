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
  packetIds: number[];
}

export interface PacketRecord {
  id: number;
  timestamp: string;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  flags: string;
  summary: string;
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
  protocols: { name: string; value: number }[];
}

export interface TrendPoint {
  time: string;
  alerts: number;
  packets: number;
}
