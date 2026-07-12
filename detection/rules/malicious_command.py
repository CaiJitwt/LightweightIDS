from __future__ import annotations

import re

from detection.rule_base import RuleBase
from detection.rules.payload_utils import packet_text
from models import AlertRecord, PacketRecord


class MaliciousCommandRule(RuleBase):
    rule_id = "MALICIOUS_COMMAND"
    name = "Malicious command detection"
    category = "web"
    severity = "CRITICAL"
    threshold = 1
    time_window = 0

    KEYWORDS = [
        "whoami",
        "net user",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "bash -i",
        "/dev/tcp",
        "powershell -enc",
        "powershell.exe -enc",
        "wget ",
        "curl ",
        "certutil",
        "nc -e",
        "ncat",
    ]

    # Regex patterns for host recon, reverse shells (7 variants), encoded
    # execution, privilege escalation, persistence, lateral movement tools,
    # data exfiltration, credential dumping (mimikatz, procdump), and
    # attack tools (nmap, hydra, sqlmap).
    REGEX_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        # ---- host reconnaissance ----
        ("hostname", re.compile(r"\bhostname\b", re.IGNORECASE)),
        ("uname", re.compile(r"\buname\s+-a\b", re.IGNORECASE)),
        ("netstat", re.compile(r"\bnetstat\s+-[a-zA-Z]*n", re.IGNORECASE)),
        ("ipconfig", re.compile(r"\bifconfig\b|\bip\s+addr\b|\bipconfig\s+/all\b", re.IGNORECASE)),
        ("systeminfo", re.compile(r"\bsysteminfo\b|\bcat\s+/proc/cpuinfo\b|\blscpu\b", re.IGNORECASE)),
        ("tasklist", re.compile(r"\btasklist\b|\bps\s+(aux|ef)\b", re.IGNORECASE)),
        ("arp_table", re.compile(r"\barp\s+-a\b|\broute\s+print\b|\broute\s+-n\b", re.IGNORECASE)),
        ("net_group", re.compile(r"\bnet\s+(localgroup|group)\b", re.IGNORECASE)),
        # ---- reverse shells ----
        ("reverse_dev_tcp", re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+")),
        ("reverse_bash_i", re.compile(r"\bbash\s+-i\s*>&\s*/dev/tcp|\bbash\s+-i\s*>\s*/dev/tcp")),
        ("reverse_python", re.compile(r"\bpython\s+-c\s+['\"]import (socket|pty|subprocess|os)\b")),
        ("reverse_nc", re.compile(r"\b(nc|netcat|ncat)\s+.*\s+-[eE]\s+/(bin/bash|bin/sh|cmd\.exe)", re.IGNORECASE)),
        ("reverse_socat", re.compile(r"\bsocat\s+.*EXEC:\s*(/bin/bash|/bin/sh|cmd)", re.IGNORECASE)),
        ("reverse_perl", re.compile(r"\bperl\s+-e\s+['\"]use Socket")),
        ("reverse_ruby", re.compile(r"\bruby\s+-e\s+['\"]require 'socket")),
        ("reverse_php", re.compile(r"\bphp\s+-r\s+['\"]\\\$sock\s*=\s*fsockopen\b")),
        ("reverse_mkfifo", re.compile(r"\bmkfifo\s+/tmp/\w+;\s*(cat|nc|sh)\b")),
        # ---- encoded execution ----
        ("powershell_enc", re.compile(r"\bpowershell\b.*\s-[eE][nN][cC]\b|\bpowershell\b.*\s-[eE][xX][eE][cC]\s+[bB][yY][pP][aA][sS][sS]\b", re.IGNORECASE)),
        ("powershell_iex", re.compile(r"\b[Ii][Ee][Xx]\s*\(.*New-Object\s+Net\.WebClient\b|\bInvoke-Expression\b", re.IGNORECASE)),
        ("powershell_download", re.compile(r"\bNew-Object\s+System\.Net\.WebClient\b.*\bDownload(String|File)\b", re.IGNORECASE)),
        ("base64_decode", re.compile(r"\bbase64\s+-d\b|\bbase64\s+--decode\b|\b-e\s+'[A-Za-z0-9+/=]{100,}'")),
        ("certutil", re.compile(r"\bcertutil\s+-urlcache\s+-split\s+-f\b|\bcertutil\s+-decode\b", re.IGNORECASE)),
        ("mshta", re.compile(r"\bmshta\s+(vbscript|javascript):", re.IGNORECASE)),
        # ---- download-execute ----
        ("wget_pipe_sh", re.compile(r"\bwget\s+.*\s+-O\s*-\s*\|\s*(sh|bash|python|perl|ruby)\b", re.IGNORECASE)),
        ("curl_pipe_sh", re.compile(r"\bcurl\s+.*\s*\|\s*(sh|bash|python|perl|ruby)\b", re.IGNORECASE)),
        ("wget_tmp", re.compile(r"\bwget\s+https?://.*\s+-O\s+/tmp\b", re.IGNORECASE)),
        ("curl_tmp", re.compile(r"\bcurl\s+.*\s+-o\s+/tmp\b", re.IGNORECASE)),
        ("bitsadmin", re.compile(r"\bbitsadmin\s+/transfer\b", re.IGNORECASE)),
        ("scp_download", re.compile(r"\bscp\s+\w+@\d+\.\d+\.\d+\.\d+:", re.IGNORECASE)),
        # ---- privilege escalation ----
        ("sudo_su", re.compile(r"\bsudo\s+(su\b|bash\b|sh\b|/bin/)", re.IGNORECASE)),
        ("su_root", re.compile(r"\bsu\s+-\s*\broot\b", re.IGNORECASE)),
        ("chmod_suid", re.compile(r"\bchmod\s+[0-7]*[4-7]77\s+\S+\b|\bchmod\s+u\+s\b", re.IGNORECASE)),
        # ---- persistence ----
        ("crontab_backdoor", re.compile(r"\bcrontab\s+-e\b|\becho\s+.*\s*>>\s*/etc/crontab\b")),
        ("reg_run_key", re.compile(r"\breg\s+add\s+.*\\Run\b|\bHKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b", re.IGNORECASE)),
        ("rc_local", re.compile(r"/etc/rc\.local\b|\bsystemctl\s+enable\s+\S+\.service\b")),
        # ---- lateral movement tools ----
        ("psexec", re.compile(r"\bpsexec\b|\bPsExec\.exe\b", re.IGNORECASE)),
        ("wmiexec", re.compile(r"\bwmiexec\b|\bInvoke-WmiMethod\b", re.IGNORECASE)),
        ("smbexec", re.compile(r"\bsmbexec\b|\bsmbclient\b.*exec", re.IGNORECASE)),
        ("schtasks_remote", re.compile(r"\bschtasks\s+/create\b.*\s+/[sS]\s+\d+\.\d+\.\d+\.\d+", re.IGNORECASE)),
        ("winrm_remote", re.compile(r"\bInvoke-Command\s+.*-ComputerName\b|\bEnter-PSSession\b", re.IGNORECASE)),
        # ---- data exfiltration ----
        ("exfil_tar", re.compile(r"\btar\s+-czf\s+-*\s*\|\s*(nc|curl|wget)\b", re.IGNORECASE)),
        ("exfil_zip", re.compile(r"\bzip\s+-r\s+-*\s*\|\s*(nc|curl|wget)\b", re.IGNORECASE)),
        # ---- credential dumping ----
        ("mimikatz", re.compile(r"\bmimikatz\b|\bsekurlsa::\b|\blsadump::\b", re.IGNORECASE)),
        ("passwd_dump", re.compile(r"\bcat\s+/etc/shadow\b|\bcopy\s+.*\\SAM\b|\bcopy\s+.*\\SYSTEM\b", re.IGNORECASE)),
        ("procdump_lsass", re.compile(r"\bprocdump\s+-ma\s+lsass\.exe\b", re.IGNORECASE)),
        # ---- attack tools ----
        ("nmap", re.compile(r"\bnmap\s+-[sS][sS]\b|\bnmap\s+-sV\b|\bnmap\s+-p\s*\d+", re.IGNORECASE)),
        ("hydra", re.compile(r"\bhydra\s+-[lL]\s+\S+\s+-[pP]\s+\S+\s+\S+:\d+\b", re.IGNORECASE)),
        ("sqlmap", re.compile(r"\bsqlmap\s+-u\s+http", re.IGNORECASE)),
        ("gobuster", re.compile(r"\bgobuster\s+dir\s+-u\s+http", re.IGNORECASE)),
        ("shell_separator", re.compile(r"(?:;|&&|\|\||\||`|\$\()\s*(whoami|id|uname|cat|type|cmd|powershell|bash|sh|nc|curl|wget)\b", re.IGNORECASE)),
        ("ip_parameter_injection", re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\s*(?:;|&&|\|\|)\s*\w+", re.IGNORECASE)),
    ]

    def process(self, packet: PacketRecord) -> list[AlertRecord]:
        text = packet_text(packet)
        matches = [kw for kw in self.KEYWORDS if kw in text]
        matches.extend(name for name, pattern in self.REGEX_PATTERNS if pattern.search(text))
        if not matches:
            return []

        return [
            self.create_alert(
                packet,
                alert_type="MALICIOUS_COMMAND",
                description="Detected suspicious system command or download-execute indicators.",
                evidence=f"matched={matches}; src={packet.src_ip}; dst={packet.dst_ip}",
            )
        ]
