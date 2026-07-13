from __future__ import annotations

from detection.analysis.attack_chain import AttackChain
from detection.llm.client import LlmClient, LlmConfig
from models import AlertRecord


SYSTEM_PROMPT = (
    "You are a network security analyst reviewing intrusion detection alerts. "
    "Respond in Chinese. Be specific about the threat, its typical position in the "
    "cyber kill chain, and concrete mitigation steps. Keep responses under 200 words."
)


class AlertAnalyzer:
    def __init__(self, client: LlmClient | None = None) -> None:
        self.client = client or LlmClient()

    def analyze(self, alert: AlertRecord) -> str:
        result = self.client.chat(self._build_prompt(alert), system=SYSTEM_PROMPT)
        if result:
            return result
        return self._expert_fallback(alert)

    def _build_prompt(self, alert: AlertRecord) -> str:
        parts = [
            f"Alert type: {alert.alert_type}",
            f"Rule: {alert.rule_name} ({alert.rule_id})",
            f"Severity: {alert.severity}",
            f"Source: {alert.src_ip or 'unknown'}:{alert.src_port or ''}",
            f"Target: {alert.dst_ip or 'unknown'}:{alert.dst_port or ''}",
            f"Protocol: {alert.protocol or 'unknown'}",
            f"Description: {alert.description}",
            f"Evidence: {alert.evidence}",
            "",
            "Format your response as:",
            "  [Threat assessment] One sentence on what this alert indicates.",
            "  [Recommended action] Concrete mitigation steps.",
            "  [Watch items] What to monitor next.",
        ]
        return "\n".join(parts)

    def _expert_fallback(self, alert: AlertRecord) -> str:
        advice = FALLBACK_ADVICE
        key = alert.alert_type or alert.rule_id
        entry = advice.get(key, advice.get("_default", ""))
        return entry.format(
            src_ip=alert.src_ip or "unknown",
            dst_ip=alert.dst_ip or "unknown",
            dst_port=alert.dst_port or "",
            severity=alert.severity,
        )

    def suggest_defense(self, alert: AlertRecord) -> dict:
        prompt = self._defense_prompt(alert)
        result = self.client.chat(prompt, system=SYSTEM_PROMPT)
        if result:
            try:
                import json
                cleaned = result.strip().lstrip("```json").rstrip("```").strip()
                return {"rule": json.loads(cleaned), "ai_generated": True}
            except Exception:
                pass
        return self._default_defense(alert)

    def _defense_prompt(self, alert: AlertRecord) -> str:
        return (
            f"Generate a JSON firewall rule for this alert. Only return JSON, no explanation.\n"
            f"Alert: {alert.alert_type} from {alert.src_ip or ''} to {alert.dst_ip or ''}:{alert.dst_port or ''}\n"
            f'Severity: {alert.severity}\n'
            f'JSON format: {{"protocol": "any", "saddr": "{alert.src_ip or ""}", '
            f'"dport": {alert.dst_port or 0}, "action": "drop", "reason": "short reason"}}'
        )

    def _default_defense(self, alert: AlertRecord) -> dict:
        return {
            "rule": {
                "protocol": "any",
                "saddr": alert.src_ip or "",
                "dport": alert.dst_port or 0,
                "action": "drop" if alert.severity in ("CRITICAL", "HIGH") else "log",
                "reason": f"Based on {alert.alert_type}",
            },
            "ai_generated": False,
        }


FALLBACK_ADVICE: dict[str, str] = {
    "PORT_SCAN": (
        "[Threat assessment] Port scanning indicates reconnaissance — the attacker is mapping "
        "services on {dst_ip} to find exploitable entry points.\n"
        "[Recommended action] Block {src_ip} at the perimeter firewall. Audit exposed services "
        "on {dst_ip} and close unnecessary ports.\n"
        "[Watch items] Monitor {src_ip} for follow-on attacks like brute force or exploit attempts."
    ),
    "HOST_SCAN": (
        "[Threat assessment] Host scanning shows {src_ip} is probing the internal network for "
        "live hosts, indicating lateral movement preparation.\n"
        "[Recommended action] Isolate {src_ip} from the network immediately. "
        "Check whether it has been compromised.\n"
        "[Watch items] Review connections from {src_ip} to other internal hosts."
    ),
    "SYN_FLOOD": (
        "[Threat assessment] SYN flood is a denial-of-service attack targeting {dst_ip}. "
        "The attacker is exhausting connection resources.\n"
        "[Recommended action] Enable SYN cookies on the target server. "
        "Rate-limit incoming SYN packets from {src_ip} at the network edge.\n"
        "[Watch items] Check if the flood is a diversion for a concurrent attack elsewhere."
    ),
    "BRUTE_FORCE": (
        "[Threat assessment] Brute force attack — {src_ip} is attempting to guess credentials "
        "on port {dst_port} of {dst_ip}.\n"
        "[Recommended action] Block {src_ip} and enable account lockout after N failed attempts. "
        "Enforce MFA if not already active.\n"
        "[Watch items] Audit recent successful logins from {src_ip} for possible compromise."
    ),
    "SQL_INJECTION": (
        "[Threat assessment] SQL injection attempt by {src_ip} targeting web application at {dst_ip}. "
        "If successful, the attacker could extract or destroy database contents.\n"
        "[Recommended action] Block {src_ip}. Urgently review the affected endpoint for input "
        "validation gaps. Use parameterized queries.\n"
        "[Watch items] Check database logs for unusual queries from the time window of this alert."
    ),
    "XSS": (
        "[Threat assessment] Cross-site scripting attempt from {src_ip}. This could steal user "
        "sessions or deface the application at {dst_ip}.\n"
        "[Recommended action] Block {src_ip}. Validate all user input is properly escaped. "
        "Enable Content-Security-Policy headers.\n"
        "[Watch items] Check if any user sessions were compromised during this timeframe."
    ),
    "WEB_ATTACK": (
        "[Threat assessment] Advanced web attack indicators from {src_ip} — could involve XXE, "
        "SSTI, deserialization, or webshell uploads targeting {dst_ip}.\n"
        "[Recommended action] Block {src_ip} immediately. Review the affected endpoint for "
        "vulnerable components. Check for uploaded webshell files.\n"
        "[Watch items] Scan {dst_ip} for newly created files and unusual process execution."
    ),
    "MALICIOUS_COMMAND": (
        "[Threat assessment] Malicious command execution detected from {src_ip}. This suggests "
        "the attacker has achieved code execution on or via {dst_ip}.\n"
        "[Recommended action] Isolate {dst_ip} immediately. Initiate incident response. "
        "Block outbound connections to the C2 address in the evidence.\n"
        "[Watch items] Collect memory dumps and process trees from {dst_ip} for forensic analysis."
    ),
    "LATERAL_MOVEMENT": (
        "[Threat assessment] Lateral movement detected — {src_ip} is spreading internally via "
        "SMB/RDP/SSH. The attacker has likely compromised a foothold host.\n"
        "[Recommended action] Isolate {src_ip} and all affected targets. "
        "Reset credentials for accounts used in the lateral movement.\n"
        "[Watch items] Map the full scope of internal connections from {src_ip}."
    ),
    "ABNORMAL_OUTBOUND": (
        "[Threat assessment] Abnormal outbound traffic from {src_ip} to external host — this "
        "matches C2 beaconing or data exfiltration patterns.\n"
        "[Recommended action] Block the external destination at the firewall. "
        "Inspect {src_ip} for malware or unauthorized remote access tools.\n"
        "[Watch items] Review all outbound connections from {src_ip} in the past 24 hours."
    ),
    "DNS_ANOMALY": (
        "[Threat assessment] DNS anomalies from {src_ip} — long domain names or high-entropy "
        "queries suggest DNS tunneling or DGA-based C2 communication.\n"
        "[Recommended action] Sinkhole the suspicious domains. "
        "Restrict outbound DNS to authorized resolvers only.\n"
        "[Watch items] Check {src_ip} for processes making unusual DNS queries."
    ),
    "TLS_WEAK_FINGERPRINT": (
        "[Threat assessment] Weak TLS configuration detected — {src_ip} is using outdated "
        "protocols or ciphers. This may indicate malware-generated traffic.\n"
        "[Recommended action] Investigate the process on {src_ip} generating this TLS session. "
        "Block the destination if confirmed malicious.\n"
        "[Watch items] Compare the JA3 fingerprint against known malware fingerprint databases."
    ),
    "ML_ANOMALY": (
        "[Threat assessment] Machine learning model flagged anomalous behavior from {src_ip}. "
        "The traffic pattern deviates significantly from established baselines.\n"
        "[Recommended action] Review the anomaly reasons in the alert evidence. "
        "If confirmed suspicious, treat as a potential zero-day or novel attack.\n"
        "[Watch items] Correlate with other alerts from {src_ip} to build context."
    ),
    "_default": (
        "[Threat assessment] This {severity}-severity alert from {src_ip} indicates suspicious "
        "activity that warrants investigation.\n"
        "[Recommended action] Review the alert evidence for specifics. "
        "If the source is external, consider blocking at the perimeter.\n"
        "[Watch items] Monitor {src_ip} for repeated or escalating behavior."
    ),
}


class ChainNarrator:
    def __init__(self, client: LlmClient | None = None) -> None:
        self.client = client or LlmClient()

    def narrate(self, chain: AttackChain) -> str:
        summary = (
            f"Attack chain from {chain.source_ip}: "
            f"{' -> '.join(chain.stages)}. "
            f"Risk score: {chain.risk_score}/100. "
            f"Total alerts: {len(chain.alerts)}. "
            f"Severities: {self._severity_summary(chain)}."
        )
        prompt = (
            "Describe this attack chain in 3-5 sentences as a security incident timeline. "
            "Use Chinese. Be specific about what each stage means.\n\n"
            f"{summary}"
        )
        result = self.client.chat(prompt, system=SYSTEM_PROMPT)
        if result:
            return result
        return self._fallback_narrative(chain)

    def _severity_summary(self, chain: AttackChain) -> str:
        counts: dict[str, int] = {}
        for a in chain.alerts:
            s = a.severity
            counts[s] = counts.get(s, 0) + 1
        return ", ".join(f"{k}:{v}" for k, v in sorted(counts.items()))

    def _fallback_narrative(self, chain: AttackChain) -> str:
        parts = [f"攻击者 {chain.source_ip} 的攻击链（风险评分 {chain.risk_score}/100）："]
        stage_desc = {
            "scan": "首先对目标进行了网络扫描和侦察，探测开放的端口和服务。",
            "exploit": "随后利用漏洞尝试获取访问权限，可能涉及 SQL 注入、XSS 或 Web 漏洞利用。",
            "execution": "成功进入后执行了恶意命令或脚本，获取了更深层的系统控制。",
            "credential_access": "尝试暴力破解或凭据窃取，获取合法账号的访问权限。",
            "c2": "建立了与外部服务器的命令控制信道，实现了持久化的远程控制。",
            "lateral_movement": "在内网中横向移动，访问其他主机以扩大控制范围。",
            "anomaly": "行为模式偏离了正常基线，表明存在异常活动。",
        }
        for stage in chain.stages:
            parts.append(stage_desc.get(stage, f"{stage} 阶段。"))
        parts.append(f"共涉及 {len(chain.alerts)} 条告警，建议立即启动应急响应流程。")
        return "\n".join(parts)
