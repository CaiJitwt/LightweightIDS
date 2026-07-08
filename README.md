# Lightweight IDS

轻量级网络入侵检测系统课程项目。项目使用 Python、PySide6、Scapy 和 SQLite，实现本地 pcap 离线检测、实时抓包、规则检测、告警管理和报告导出。

## 功能状态

- 已完成：项目骨架、数据模型、SQLite 初始化、PySide6 GUI、pcap 导入、Scapy 解析、PacketRecord 表格显示。
- 已完成：DetectionEngine、5 个核心检测规则、告警中心、SQLite 告警保存、HTML/CSV/JSON 报告导出。
- 已完成：规则管理、黑名单管理、仪表盘统计、实时抓包、自定义规则。
- 已增强：常见协议识别，减少实时抓包中大量 `UNKNOWN` 的情况。

## 技术栈

- Python 3.11+
- PySide6
- Scapy
- SQLite
- PyYAML
- pytest

## 安装与运行

```powershell
.conda\Lightweight-IDS\python.exe -m pip install -r requirements.txt
.conda\Lightweight-IDS\python.exe main.py
```

首次启动会自动初始化数据库：

```text
data/lightweight_ids.db
```

## pcap 导入

进入“流量监控”，点击“导入 pcap”，选择本地 `.pcap`、`.pcapng` 或 `.cap` 文件。系统会在后台线程中读取数据包，转换为统一的 `PacketRecord`，并显示时间、源 IP、目标 IP、协议、端口、长度和摘要。

当前常见协议识别包括 TCP、UDP、ICMP、ICMPv6、IPv4、IPv6、ARP、DNS、HTTP、HTTPS、DHCP、mDNS、LLMNR、NBNS、NTP、QUIC 等。无法归入上述类型时，会尽量显示 Scapy 的原始层名称，减少 `UNKNOWN`。

## 检测规则

内置 5 个核心检测规则：

- 端口扫描检测
- SYN Flood 检测
- ICMP Flood 检测
- 敏感端口访问检测
- 黑名单 IP 检测

## 自定义规则

进入“规则管理”，可以新增、保存、删除自定义规则。自定义规则支持按以下条件组合匹配：

- 协议
- 源 IP
- 目标 IP
- 源端口
- 目标端口
- 关键字，匹配数据包摘要、DNS 查询、HTTP method/host/path

条件为空表示不限制。自定义规则只做字段匹配和告警生成，不执行脚本，也不会主动访问任何目标。

## 告警中心与报告

pcap 导入和实时抓包会同步运行检测引擎，生成的告警会写入 SQLite。进入“告警中心”可以按等级筛选、关键字搜索、查看详情、确认或忽略告警，并导出 CSV。

进入“报告导出”可以导出：

- HTML 检测报告
- 告警 CSV
- 告警 JSON

## 实时抓包

进入“流量监控”，点击“刷新网卡”后选择网卡，再点击“开始抓包”。Windows 下实时抓包通常需要安装 Npcap，并可能需要管理员权限。

实时抓包只被动接收本机网卡流量，不会扫描或攻击任何目标。

## 测试

如果 Windows 默认临时目录权限导致 pytest 无法创建临时文件，可使用项目内临时目录运行：

```powershell
.conda\Lightweight-IDS\python.exe -m pytest --basetemp .test_tmp -o cache_dir=.test_cache
```

最近一次验证结果：25 passed。

## 课程项目声明

本项目仅用于教学、实验和防御性检测，不用于任何未授权测试、扫描或攻击。
