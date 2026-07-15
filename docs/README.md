# Lightweight IDS Documentation

[English](README.md) | [简体中文](README.zh-CN.md) | [Project README](../README.md)

This directory contains user-facing guides, architecture notes, test records, and historical planning material. Documents under **Current Guides** describe the implemented project. Documents under **Planning And Research Notes** may contain proposals that are not part of the current runtime.

## Current Guides

| Document | Purpose | Language |
| --- | --- | --- |
| [User Manual](user_manual.md) | Installation, capture, alert review, rules, investigations, reset, and troubleshooting | English |
| [用户手册](user_manual.zh-CN.md) | 安装、抓包、告警核实、规则、调查、重置和故障排查 | 简体中文 |
| [System Design](system_design.md) | Current architecture, data flow, storage, and security boundaries | English |
| [Modern Frontend README](../modern_frontend/README.md) | Modern launcher, local API, frontend development, and verification | English |
| [HTTPS Lab Workflow](https_lab_workflow.md) | Authorized plaintext HTTP import and TLS-analysis boundaries | English |
| [Protection Workflow](protection_workflow.md) | Blocklist and defensive enforcement workflow | English |
| [Demo Guide](demo_guide.md) | Deterministic attack-chain pcap demonstration | 简体中文 |
| [Sample Data README](../sample_data/README.md) | Sample-data contents and regeneration | English |
| [Test Report](test_report.md) | Recorded verification scope and test notes | English |

## Planning And Research Notes

The following files are retained as design history. Check the current source code and user manual before treating an item as implemented.

- [Extension Ideas](extension_ideas.md)
- [Extension Development Plan](extension_development_plan.md)
- [Further Implementation Plan](further_implementation_plan.md)
- [Modern Frontend Endpoint Security Plan](modern_frontend_endpoint_security_plan.md)
- [Runtime Hardening Plan](runtime_hardening_plan.md)
- [Project Plan](project_plan.md)
- [Nightly Improvement Plan](nightly_improvement_plan.md)

## Documentation Rules

- Keep visible application names and UI labels in English when documenting exact controls.
- Describe TLS detections as metadata or fingerprint risk; do not imply HTTPS payload decryption.
- Distinguish detection from prevention. A block is enforced only when the operating-system status is `Active`.
- Treat alerts and sustained resource usage as analyst review signals, not proof of compromise.
- Update both root README files when installation, launch commands, major modules, or safety boundaries change.
