# Lightweight IDS 测试报告

## 测试环境

- 操作系统：Windows。
- Python：项目内 Conda 环境 Python 3.11。
- 测试框架：pytest。
- 主要依赖：PySide6、Scapy、PyYAML。

## 测试命令

```powershell
.\.conda\Lightweight-IDS\python.exe -m pytest --basetemp .test_tmp -o cache_dir=.test_cache
```

## 最近一次测试结果

```text
46 passed
```

## 覆盖范围

- 数据模型校验。
- SQLite 初始化和默认规则补齐。
- pcap 加载。
- Scapy 数据包解析。
- 检测引擎启用、禁用和告警冷却。
- 核心规则：端口扫描、SYN Flood、ICMP Flood、敏感端口、黑名单。
- 阶段一扩展规则：SQL 注入、XSS、HTTP 可疑请求、恶意命令、暴力破解、DNS 异常。
- 阶段二异常行为规则：异常外联、横向移动、主机扫描。
- 阶段三扩展能力：TLS 指纹风险、轻量异常评分、攻击链分析、误报降噪。
- 告警仓储和报告导出。

## 手动验收建议

1. 启动程序并进入仪表盘，确认页面可打开。
2. 导入一个 pcap 文件，确认流量表格出现数据包。
3. 在规则管理页确认默认规则数量为 16 条。
4. 修改一个规则阈值并保存，重启后确认该阈值仍保留。
5. 在告警中心确认告警筛选、搜索、详情和 CSV 导出可用。
6. 导入带有多阶段行为的测试流量后，查看攻击链视图和仪表盘时间线。

## 已知限制

- TLS 指纹分析基于解析到的握手或摘要文本做轻量匹配，不是完整 JA3/JA4 实现。
- 轻量异常评分为规则化启发式模型，不依赖 sklearn，也不提供训练流程。
- 实时抓包依赖本机网卡权限和 Npcap 环境。
