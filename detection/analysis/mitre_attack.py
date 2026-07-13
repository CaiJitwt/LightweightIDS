from __future__ import annotations

from dataclasses import dataclass

TACTIC_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    description: str = ""


RULE_TECHNIQUES: dict[str, list[Technique]] = {
    "PORT_SCAN": [
        Technique("T1046", "Network Service Discovery", "Scanning for open ports and services on target hosts."),
        Technique("T1595", "Active Scanning", "Actively probing target infrastructure for vulnerabilities."),
    ],
    "HOST_SCAN": [
        Technique("T1018", "Remote System Discovery", "Discovering remote systems on the network."),
        Technique("T1046", "Network Service Discovery", "Probing for reachable hosts and services."),
    ],
    "SYN_FLOOD": [
        Technique("T1498", "Network Denial of Service", "Flooding targets with network traffic to disrupt service."),
        Technique("T1499", "Endpoint Denial of Service", "Resource exhaustion at the endpoint level."),
    ],
    "ICMP_FLOOD": [
        Technique("T1498", "Network Denial of Service", "ICMP-based flooding for denial of service."),
    ],
    "SENSITIVE_PORT": [
        Technique("T1046", "Network Service Discovery", "Identifying sensitive service ports."),
        Technique("T1190", "Exploit Public-Facing Application", "Targeting exposed services for exploitation."),
    ],
    "BLACKLIST_IP": [
        Technique("T1071", "Application Layer Protocol", "Communication with known-malicious addresses."),
    ],
    "BRUTE_FORCE": [
        Technique("T1110", "Brute Force", "Attempting to guess credentials through repeated logins."),
        Technique("T1078", "Valid Accounts", "Using brute-forced credentials to gain access."),
    ],
    "DNS_ANOMALY": [
        Technique("T1071.004", "DNS Tunneling", "Using DNS queries for command and control or data exfiltration."),
        Technique("T1568.001", "Domain Generation Algorithms", "Algorithmically generated domain names for C2."),
    ],
    "HTTP_SUSPICIOUS": [
        Technique("T1190", "Exploit Public-Facing Application", "Web attack patterns including traversal and SSRF."),
        Technique("T1083", "File and Directory Discovery", "Probing for sensitive files and directories."),
    ],
    "SQL_INJECTION": [
        Technique("T1190", "Exploit Public-Facing Application", "SQL injection against web application."),
        Technique("T1592", "Gather Victim Host Information", "Exfiltrating data via SQL injection."),
    ],
    "XSS": [
        Technique("T1189", "Drive-by Compromise", "Cross-site scripting for session theft or content injection."),
        Technique("T1059.007", "JavaScript", "Malicious script execution in victim browser."),
    ],
    "WEB_ATTACK": [
        Technique("T1190", "Exploit Public-Facing Application", "Advanced web attacks including XXE, SSTI, deserialization."),
        Technique("T1505.003", "Web Shell", "Deploying web shells for persistent access."),
        Technique("T1059", "Command and Scripting Interpreter", "Code execution via template injection or deserialization."),
    ],
    "MALICIOUS_COMMAND": [
        Technique("T1059", "Command and Scripting Interpreter", "Malicious command execution on compromised host."),
        Technique("T1059.001", "PowerShell", "PowerShell-based code execution."),
        Technique("T1059.003", "Windows Command Shell", "Windows cmd-based execution."),
        Technique("T1059.004", "Unix Shell", "Unix shell-based command execution and reverse shells."),
    ],
    "ABNORMAL_OUTBOUND": [
        Technique("T1071", "Application Layer Protocol", "C2 communication over application protocols."),
        Technique("T1571", "Non-Standard Port", "C2 communication over non-standard ports."),
        Technique("T1095", "Non-Application Layer Protocol", "C2 over non-HTTP protocols."),
    ],
    "LATERAL_MOVEMENT": [
        Technique("T1021.002", "SMB/Windows Admin Shares", "Lateral movement via SMB administrative shares."),
        Technique("T1021.001", "Remote Desktop Protocol", "Lateral movement through RDP connections."),
        Technique("T1021.004", "SSH", "Lateral movement via SSH."),
    ],
    "TLS_FINGERPRINT": [
        Technique("T1573", "Encrypted Channel", "C2 communication over encrypted TLS channels."),
        Technique("T1001.003", "Protocol Impersonation", "Malware-generated TLS with weak or unusual fingerprints."),
    ],
    "ML_ANOMALY": [
        Technique("T1071", "Application Layer Protocol", "Anomalous behavior detected by ML model."),
    ],
    "ML_FLOW_ANOMALY": [
        Technique("T1071", "Application Layer Protocol", "Flow-level anomalous behavior detected by ML model."),
    ],
    "SIGNATURE_MATCH": [
        Technique("T1071", "Application Layer Protocol", "Traffic matching known threat signatures."),
        Technique("T1203", "Exploitation for Client Execution", "Exploitation signatures detected in traffic."),
    ],
    "BASELINE_DEVIATION": [
        Technique("T1071", "Application Layer Protocol", "Host behavior deviating from established baseline."),
    ],
    "BANDWIDTH_SPIKE": [
        Technique("T1048", "Exfiltration Over Alternative Protocol", "Large data transfers indicating possible exfiltration."),
        Technique("T1498", "Network Denial of Service", "Bandwidth spikes consistent with DoS activity."),
    ],
    "SESSION_DURATION_ANOMALY": [
        Technique("T1071", "Application Layer Protocol", "Abnormally long sessions suggesting C2 or interactive access."),
        Technique("T1021", "Remote Services", "Extended remote service sessions."),
    ],
}


def techniques_for_rule(rule_id: str) -> list[Technique]:
    return RULE_TECHNIQUES.get(rule_id, [])


def tactic_for_technique(technique_id: str) -> str:
    _tech_to_tactic = {
        "T1046": "discovery",
        "T1595": "reconnaissance",
        "T1018": "discovery",
        "T1498": "impact",
        "T1499": "impact",
        "T1190": "initial_access",
        "T1189": "initial_access",
        "T1203": "execution",
        "T1071": "command_and_control",
        "T1071.004": "command_and_control",
        "T1568.001": "command_and_control",
        "T1083": "discovery",
        "T1592": "reconnaissance",
        "T1110": "credential_access",
        "T1078": "credential_access",
        "T1059": "execution",
        "T1059.001": "execution",
        "T1059.003": "execution",
        "T1059.004": "execution",
        "T1059.007": "execution",
        "T1505.003": "persistence",
        "T1571": "command_and_control",
        "T1095": "command_and_control",
        "T1021": "lateral_movement",
        "T1021.001": "lateral_movement",
        "T1021.002": "lateral_movement",
        "T1021.004": "lateral_movement",
        "T1573": "command_and_control",
        "T1001.003": "command_and_control",
        "T1048": "exfiltration",
    }
    return _tech_to_tactic.get(technique_id, "command_and_control")


def build_coverage_matrix() -> dict[str, list[tuple[str, str]]]:
    matrix: dict[str, list[tuple[str, str]]] = {tactic: [] for tactic in TACTIC_ORDER}
    for rule_id, techniques in RULE_TECHNIQUES.items():
        for tech in techniques:
            tactic = tactic_for_technique(tech.id)
            if tactic in matrix:
                matrix[tactic].append((tech.id, rule_id))
    return matrix
