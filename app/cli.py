from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.constants import PROJECT_ROOT
from capture.pcap_loader import PcapLoader
from detection.analysis.attack_chain import AttackChainAnalyzer
from detection.analysis.mitre_attack import techniques_for_rule, build_coverage_matrix
from detection.engine import DetectionEngine
from parser.packet_parser import PacketParser
from report.report_generator import ReportGenerator


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightweight-ids",
        description="Lightweight IDS — offline batch analysis",
    )
    parser.add_argument("--input", "-i", required=True, help="Path to pcap file")
    parser.add_argument("--output", "-o", default="report.html", help="HTML report output path")
    parser.add_argument("--format", "-f", choices=["html", "json"], default="html", help="Report format")
    parser.add_argument("--no-save", action="store_true", help="Skip writing packets to database")
    parser.add_argument("--cooldown", type=int, default=10, help="Alert cooldown in seconds (default: 10)")

    args = parser.parse_args(argv)

    pcap_path = Path(args.input)
    if not pcap_path.exists():
        print(f"Error: pcap file not found: {pcap_path}", file=sys.stderr)
        return 1

    print(f"Loading: {pcap_path}")
    loader = PcapLoader()
    parser_obj = PacketParser()
    engine = DetectionEngine.with_default_rules(alert_cooldown_seconds=args.cooldown)
    chain_analyzer = AttackChainAnalyzer()

    packets = []
    alerts = []
    skipped = 0

    for raw in loader.load(pcap_path):
        try:
            packet = parser_obj.parse(raw)
            alerts.extend(engine.process_packet(packet))
            packets.append(packet)
        except Exception:
            skipped += 1

    print(f"Parsed {len(packets)} packets, {len(alerts)} alerts, skipped {skipped}")

    # Statistics
    severity_dist: dict[str, int] = {}
    type_dist: dict[str, int] = {}
    rule_dist: dict[str, int] = {}
    for a in alerts:
        severity_dist[a.severity] = severity_dist.get(a.severity, 0) + 1
        type_dist[a.alert_type] = type_dist.get(a.alert_type, 0) + 1
        rule_dist[a.rule_id] = rule_dist.get(a.rule_id, 0) + 1

    high_or_critical = severity_dist.get("HIGH", 0) + severity_dist.get("CRITICAL", 0)

    # Attack chains
    chains = chain_analyzer.analyze(alerts)

    # MITRE ATT&CK coverage
    rule_ids_seen = set(rule_dist.keys())
    techniques_covered: list[tuple[str, str, str]] = []
    for rid in sorted(rule_ids_seen):
        for tech in techniques_for_rule(rid):
            techniques_covered.append((tech.id, tech.name, rid))

    # Top source IPs
    src_counts: dict[str, int] = {}
    for a in alerts:
        if a.src_ip:
            src_counts[a.src_ip] = src_counts.get(a.src_ip, 0) + 1
    top_src = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    statistics = {
        "packet_count": len(packets),
        "alert_count": len(alerts),
        "skipped_count": skipped,
        "high_or_critical": high_or_critical,
        "rules_triggered": len(rule_ids_seen),
        "severity_distribution": severity_dist,
        "alert_type_distribution": type_dist,
        "top_src_ips": top_src,
        "attack_chain_count": len(chains),
        "techniques_covered": [{"id": t[0], "name": t[1], "rule": t[2]} for t in techniques_covered],
    }

    if args.format == "json":
        output = {
            "statistics": statistics,
            "alerts": [
                {
                    "timestamp": a.timestamp,
                    "severity": a.severity,
                    "rule_id": a.rule_id,
                    "alert_type": a.alert_type,
                    "src_ip": a.src_ip,
                    "dst_ip": a.dst_ip,
                    "src_port": a.src_port,
                    "dst_port": a.dst_port,
                    "protocol": a.protocol,
                    "description": a.description,
                    "evidence": a.evidence,
                }
                for a in alerts
            ],
            "attack_chains": [
                {
                    "source_ip": c.source_ip,
                    "target_ip": c.target_ip,
                    "stages": c.stages,
                    "risk_score": c.risk_score,
                    "alert_count": len(c.alerts),
                }
                for c in chains
            ],
            "mitre_coverage": {
                tactic: [(tech_id, rule_id) for tech_id, rule_id in techs]
                for tactic, techs in build_coverage_matrix().items()
                if techs
            },
        }
        output_path = Path(args.output).with_suffix(".json")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"JSON report: {output_path}")
    else:
        report_gen = ReportGenerator()
        output_path = Path(args.output).with_suffix(".html")
        report_gen.generate_html_report(alerts, packets, statistics, output_path)
        print(f"HTML report: {output_path}")

    # Summary
    print()
    print(f"Rules triggered: {len(rule_ids_seen)}")
    for rule_id in sorted(rule_ids_seen):
        print(f"  {rule_id}: {rule_dist[rule_id]} alerts")
    print(f"MITRE ATT&CK techniques covered: {len(techniques_covered)}")
    print(f"Attack chains found: {len(chains)}")
    for chain in chains[:5]:
        print(f"  {chain.source_ip} -> {chain.summary} (risk: {chain.risk_score})")

    return 0
