import type { AlertRecord, HostRecord, PacketRecord, TrendPoint } from "../types";

export const trendData: TrendPoint[] = [
  { time: "09:00", alerts: 2, packets: 420 },
  { time: "10:00", alerts: 3, packets: 680 },
  { time: "11:00", alerts: 2, packets: 590 },
  { time: "12:00", alerts: 6, packets: 910 },
  { time: "13:00", alerts: 4, packets: 780 },
  { time: "14:00", alerts: 11, packets: 1240 },
  { time: "15:00", alerts: 5, packets: 870 },
  { time: "16:00", alerts: 7, packets: 1020 },
  { time: "17:00", alerts: 4, packets: 760 },
  { time: "18:00", alerts: 3, packets: 610 },
  { time: "19:00", alerts: 5, packets: 830 },
  { time: "20:00", alerts: 4, packets: 720 },
];

export const packets: PacketRecord[] = [
  { id: 8421, timestamp: "20:42:18.221", source: "10.0.0.24:51844", destination: "10.0.0.8:443", protocol: "TLS", length: 517, flags: "PA", summary: "TLS application data; metadata only" },
  { id: 8420, timestamp: "20:42:18.195", source: "10.0.0.8:443", destination: "10.0.0.24:51844", protocol: "TLS", length: 1280, flags: "PA", summary: "TLS application data; metadata only" },
  { id: 8419, timestamp: "20:42:17.902", source: "10.0.0.17:60211", destination: "1.1.1.1:53", protocol: "DNS", length: 82, flags: "", summary: "Query A api.internal.example" },
  { id: 8418, timestamp: "20:42:17.770", source: "10.0.0.31:54432", destination: "10.0.0.12:445", protocol: "TCP", length: 66, flags: "S", summary: "TCP connection attempt to SMB service" },
  { id: 8417, timestamp: "20:42:17.592", source: "10.0.0.24:51844", destination: "10.0.0.8:443", protocol: "TLS", length: 493, flags: "PA", summary: "TLS application data; metadata only" },
  { id: 8416, timestamp: "20:42:17.441", source: "10.0.0.5:5353", destination: "224.0.0.251:5353", protocol: "MDNS", length: 164, flags: "", summary: "Multicast DNS service announcement" },
  { id: 8415, timestamp: "20:42:17.214", source: "10.0.0.42:49822", destination: "10.0.0.1:22", protocol: "TCP", length: 60, flags: "S", summary: "TCP connection attempt to SSH service" },
  { id: 8414, timestamp: "20:42:16.998", source: "10.0.0.8:443", destination: "10.0.0.24:51844", protocol: "TLS", length: 1420, flags: "PA", summary: "TLS application data; metadata only" },
];

export const alerts: AlertRecord[] = [
  { id: 219, timestamp: "20:41:58", severity: "CRITICAL", ruleId: "LATERAL_MOVEMENT", ruleName: "Lateral movement", source: "10.0.0.31:54432", destination: "10.0.0.12:445", protocol: "TCP", description: "Internal host contacted multiple administrative services.", evidence: "targets=6; services=SMB,RDP; window=60s", status: "unconfirmed", packetIds: [8418, 8392, 8368] },
  { id: 218, timestamp: "20:39:14", severity: "HIGH", ruleId: "HOST_SCAN", ruleName: "Host scan", source: "10.0.0.42:49822", destination: "10.0.0.1:22", protocol: "TCP", description: "Source contacted many destination hosts in a short window.", evidence: "unique_targets=34; window=10s", status: "confirmed", packetIds: [8415, 8401] },
  { id: 217, timestamp: "20:35:02", severity: "MEDIUM", ruleId: "DNS_ANOMALY", ruleName: "DNS anomaly", source: "10.0.0.17:60211", destination: "1.1.1.1:53", protocol: "DNS", description: "DNS query frequency exceeded the local baseline.", evidence: "queries=48; baseline=14; window=60s", status: "unconfirmed", packetIds: [8419] },
  { id: 216, timestamp: "20:31:27", severity: "HIGH", ruleId: "TLS_FINGERPRINT", ruleName: "TLS fingerprint risk", source: "10.0.0.24:51844", destination: "10.0.0.8:443", protocol: "TLS", description: "TLS metadata indicates a weak protocol fingerprint.", evidence: "version=TLS1.0; metadata_only=true", status: "ignored", packetIds: [8421, 8420, 8417] },
  { id: 215, timestamp: "20:22:43", severity: "LOW", ruleId: "SENSITIVE_PORT", ruleName: "Sensitive port access", source: "10.0.0.9:58220", destination: "10.0.0.1:22", protocol: "TCP", description: "Observed access to a monitored administrative service.", evidence: "dst_port=22; attempts=2", status: "confirmed", packetIds: [8381] },
];

export const hosts: HostRecord[] = [
  { ip: "10.0.0.31", name: "Finance-WS31", role: "Workstation", risk: 92, importance: 70, packets: 1842, alerts: 8, lastSeen: "20:42:18", protocols: [{ name: "SMB", value: 44 }, { name: "TLS", value: 31 }, { name: "DNS", value: 15 }, { name: "Other", value: 10 }] },
  { ip: "10.0.0.42", name: "Lab-WS42", role: "Workstation", risk: 81, importance: 55, packets: 1120, alerts: 5, lastSeen: "20:42:17", protocols: [{ name: "TCP", value: 49 }, { name: "TLS", value: 28 }, { name: "DNS", value: 13 }, { name: "Other", value: 10 }] },
  { ip: "10.0.0.12", name: "Files-01", role: "Server", risk: 64, importance: 90, packets: 4560, alerts: 3, lastSeen: "20:42:18", protocols: [{ name: "SMB", value: 52 }, { name: "TLS", value: 22 }, { name: "TCP", value: 18 }, { name: "Other", value: 8 }] },
  { ip: "10.0.0.17", name: "Build-Agent", role: "Server", risk: 43, importance: 65, packets: 2980, alerts: 2, lastSeen: "20:42:17", protocols: [{ name: "TLS", value: 55 }, { name: "DNS", value: 25 }, { name: "TCP", value: 14 }, { name: "Other", value: 6 }] },
  { ip: "10.0.0.24", name: "Design-WS24", role: "Workstation", risk: 22, importance: 40, packets: 3750, alerts: 1, lastSeen: "20:42:18", protocols: [{ name: "TLS", value: 72 }, { name: "DNS", value: 12 }, { name: "MDNS", value: 10 }, { name: "Other", value: 6 }] },
];

export const severityDistribution = [
  { name: "Critical", value: 2, color: "#b42318" },
  { name: "High", value: 7, color: "#e5484d" },
  { name: "Medium", value: 12, color: "#d97706" },
  { name: "Low", value: 8, color: "#2563eb" },
];
