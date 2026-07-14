export interface RuleGuidance {
  method: string;
  threshold: string;
  window: string;
}

const IMMEDIATE_WINDOW = "Not used. A value of 0 means the rule evaluates each packet immediately.";

export const RULE_GUIDANCE: Record<string, RuleGuidance> = {
  PORT_SCAN: {
    method: "Counts distinct destination ports contacted by one source on the same target.",
    threshold: "Distinct destination ports required before an alert is raised.",
    window: "Seconds in which those distinct ports must be observed.",
  },
  SYN_FLOOD: {
    method: "Counts TCP SYN requests from one source to the same target.",
    threshold: "SYN packet count required to trigger the flood alert.",
    window: "Rolling observation period in seconds.",
  },
  ICMP_FLOOD: {
    method: "Counts ICMP packets from one source to the same target.",
    threshold: "ICMP packet count required to trigger the flood alert.",
    window: "Rolling observation period in seconds.",
  },
  SENSITIVE_PORT: {
    method: "Matches traffic against the built-in sensitive service port list.",
    threshold: "Not used beyond the first matching packet.",
    window: IMMEDIATE_WINDOW,
  },
  BLACKLIST_IP: {
    method: "Matches source and destination fields against enabled local blocklist entries.",
    threshold: "Not used beyond the first matching packet.",
    window: IMMEDIATE_WINDOW,
  },
  BRUTE_FORCE: {
    method: "Counts repeated connection attempts to monitored authentication services.",
    threshold: "Connection attempts required for the same source, target and service.",
    window: "Seconds in which the attempts must occur.",
  },
  DNS_ANOMALY: {
    method: "Combines DNS query-rate checks with long-domain and high-entropy label checks.",
    threshold: "DNS queries from one source required for the rate-based alert.",
    window: "Rolling period for query-rate counting; domain pattern checks are immediate.",
  },
  HTTP_SUSPICIOUS: {
    method: "Matches decoded HTTP text against traversal, SSRF, file inclusion and risky path indicators.",
    threshold: "Not used beyond the first matching request.",
    window: IMMEDIATE_WINDOW,
  },
  SQL_INJECTION: {
    method: "Matches decoded HTTP payload text against SQL injection indicators.",
    threshold: "Not used beyond the first matching request.",
    window: IMMEDIATE_WINDOW,
  },
  XSS: {
    method: "Matches decoded HTTP payload text against script and browser-execution indicators.",
    threshold: "Not used beyond the first matching request.",
    window: IMMEDIATE_WINDOW,
  },
  MALICIOUS_COMMAND: {
    method: "Matches payload text against command execution, reverse shell and download-execute patterns.",
    threshold: "Not used beyond the first matching request.",
    window: IMMEDIATE_WINDOW,
  },
  ABNORMAL_OUTBOUND: {
    method: "Checks internal-to-public connections for uncommon ports and fixed-interval heartbeat behavior.",
    threshold: "Connections or heartbeat samples required; high-risk ports may alert immediately.",
    window: "Maximum heartbeat interval and rolling connection period in seconds.",
  },
  LATERAL_MOVEMENT: {
    method: "Tracks internal SMB, RPC, RDP, SSH and WinRM activity across targets or services.",
    threshold: "Distinct targets, or events against one target using at least two services, required to alert.",
    window: "Seconds in which the internal activity must be observed.",
  },
  HOST_SCAN: {
    method: "Counts distinct destination hosts contacted by one source.",
    threshold: "Distinct destination hosts required to trigger the scan alert.",
    window: "Seconds in which those destinations must be contacted.",
  },
  TLS_FINGERPRINT: {
    method: "Evaluates TLS metadata for weak versions, weak ciphers and suspicious certificate indicators.",
    threshold: "Not used beyond the first risky metadata match.",
    window: IMMEDIATE_WINDOW,
  },
  ML_ANOMALY: {
    method: "Calculates a lightweight packet anomaly score from protocol, port and size features.",
    threshold: "Minimum anomaly score from 0 to 100 required to alert.",
    window: IMMEDIATE_WINDOW,
  },
  WEB_ATTACK: {
    method: "Matches advanced web indicators including SSRF, XXE, SSTI, webshell and deserialization patterns.",
    threshold: "Not used beyond the first matching request.",
    window: IMMEDIATE_WINDOW,
  },
  ML_FLOW_ANOMALY: {
    method: "Scores aggregated flow features with IsolationForest when available or a lightweight fallback.",
    threshold: "Minimum flow anomaly score from 0 to 100 required to alert.",
    window: "Flow feature aggregation period in seconds.",
  },
  SIGNATURE_MATCH: {
    method: "Matches packet fields and payload text against the external defensive signature library.",
    threshold: "Not used beyond the first signature match.",
    window: IMMEDIATE_WINDOW,
  },
  BASELINE_DEVIATION: {
    method: "Compares current packet, byte, destination and port activity with the learned host baseline.",
    threshold: "Multiplier applied to the historical baseline before alerting.",
    window: "Current activity aggregation period in seconds.",
  },
  BANDWIDTH_SPIKE: {
    method: "Compares current outbound byte volume with the learned host byte baseline.",
    threshold: "Multiplier applied to baseline byte volume before alerting.",
    window: "Byte-volume aggregation period in seconds.",
  },
  SESSION_DURATION_ANOMALY: {
    method: "Compares monitored remote-service session duration with the host historical average.",
    threshold: "Multiplier applied to the historical average duration before alerting.",
    window: "Idle gap in seconds after which a new session is started.",
  },
  WINDOWS_LOGON_FAILURE: {
    method: "Counts Windows event 4625 authentication failures by source address, user or local host.",
    threshold: "Authentication failures required before an alert is generated.",
    window: "Rolling failure-count period in seconds.",
  },
  WINDOWS_PERSISTENCE: {
    method: "Matches service and scheduled-task creation or modification events 4697, 4698, 4702 and 7045.",
    threshold: "Not used beyond the first matching persistence event.",
    window: IMMEDIATE_WINDOW,
  },
  WINDOWS_PRIVILEGE_CHANGE: {
    method: "Matches account creation and privileged group membership events 4720, 4728 and 4732.",
    threshold: "Not used beyond the first matching account or group change.",
    window: IMMEDIATE_WINDOW,
  },
  POWERSHELL_SUSPICIOUS: {
    method: "Scores PowerShell 4103 and 4104 content for encoded commands, download cradles, policy bypass and credential tooling.",
    threshold: "Distinct suspicious indicators required in one PowerShell event (default: 3).",
    window: IMMEDIATE_WINDOW,
  },
  SECURITY_CONTROL_TAMPER: {
    method: "Matches Security log clearing and Defender protection-disable events 1102 and 5001.",
    threshold: "Not used beyond the first matching security-control event.",
    window: IMMEDIATE_WINDOW,
  },
  RDP_LATERAL_ACTIVITY: {
    method: "Counts remote interactive logons and Terminal Services session events by source or account.",
    threshold: "Remote session events required before an alert is generated.",
    window: "Rolling remote-session observation period in seconds.",
  },
};

export const FALLBACK_RULE_GUIDANCE: RuleGuidance = {
  method: "Evaluates packets using the rule-specific detection implementation.",
  threshold: "Rule-specific activation count or score.",
  window: "Rule-specific observation period in seconds; 0 means immediate evaluation.",
};
