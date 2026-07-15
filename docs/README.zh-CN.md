# Lightweight IDS 文档

[English](README.md) | [简体中文](README.zh-CN.md) | [项目 README](../README.zh-CN.md)

本目录包含用户指南、架构说明、测试记录和历史规划材料。**当前使用文档**描述已经实现的项目；**规划与研究记录**可能包含尚未进入当前运行版本的建议，不能直接视为现有功能。

## 当前使用文档

| 文档 | 用途 | 语言 |
| --- | --- | --- |
| [User Manual](user_manual.md) | 安装、抓包、告警核实、规则、调查、重置和故障排查 | English |
| [用户手册](user_manual.zh-CN.md) | 安装、抓包、告警核实、规则、调查、重置和故障排查 | 简体中文 |
| [System Design](system_design.md) | 当前架构、数据流程、存储设计和安全边界 | English |
| [现代前端 README](../modern_frontend/README.md) | 现代启动器、本地 API、前端开发和验证方式 | English |
| [HTTPS 实验流程](https_lab_workflow.md) | 授权明文 HTTP 导入和 TLS 分析边界 | English |
| [防护工作流](protection_workflow.md) | 黑名单和防御执行流程 | English |
| [演示指南](demo_guide.md) | 确定性攻击链 pcap 演示 | 简体中文 |
| [示例数据说明](../sample_data/README.md) | 示例数据内容和重新生成方式 | English |
| [测试报告](test_report.md) | 已记录的验证范围和测试说明 | English |

## 规划与研究记录

以下文件作为设计历史保留。将其中内容视为已实现功能前，应先检查当前源代码和用户手册。

- [扩展思路](extension_ideas.md)
- [扩展开发计划](extension_development_plan.md)
- [后续实现计划](further_implementation_plan.md)
- [现代前端端点安全计划](modern_frontend_endpoint_security_plan.md)
- [运行加固计划](runtime_hardening_plan.md)
- [项目计划](project_plan.md)
- [夜间改进计划](nightly_improvement_plan.md)

## 文档维护约定

- 引用界面中的具体控件时，保留实际英文 UI 名称。
- TLS 检测只能描述为元数据或指纹风险，不得暗示程序能够解密 HTTPS 正文。
- 明确区分检测和阻断。只有操作系统执行状态为 `Active` 时，流量才真正被阻断。
- 告警和长期资源高负载仅属于人工排查信号，不是主机感染的直接证明。
- 安装方式、启动命令、主要模块或安全边界发生变化时，应同步更新根目录的中英文 README。
