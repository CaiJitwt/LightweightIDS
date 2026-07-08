# Lightweight IDS

轻量级网络入侵检测系统课程项目。当前版本包含项目骨架、数据模型、SQLite 初始化、PySide6 GUI 页面，以及离线 pcap 导入与 Scapy 基础解析。

## 功能状态

- 已完成：项目骨架、配置文件、日志初始化、数据模型、数据库表初始化、GUI 主窗口、pcap 文件导入、Scapy 解析、PacketRecord 表格显示、检测引擎、5 个核心检测规则、告警中心、SQLite 告警保存、HTML/CSV/JSON 报告导出、规则管理、仪表盘统计、实时抓包。
- 后续可扩展：更多检测规则、图表美化、PyInstaller 打包、课程演示样例数据。

## 技术栈

- Python 3.11+
- PySide6
- SQLite
- PyYAML
- Scapy

## 安装

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 运行

```powershell
python main.py
```

首次启动会自动创建数据库文件：

```text
data/lightweight_ids.db
```

## pcap 导入

启动 GUI 后进入“流量监控”，点击“导入 pcap”，选择本地 `.pcap`、`.pcapng` 或 `.cap` 文件。系统会在后台线程中读取数据包，转换为统一的 `PacketRecord`，并显示时间、源 IP、目标 IP、协议、端口、长度和摘要。

当前解析字段包括：

- IPv4 / IPv6 源地址和目标地址
- TCP / UDP / ICMP / DNS / HTTP 基础协议识别
- TCP flags
- DNS 查询域名
- HTTP method、host、path

## 检测规则

当前已实现 5 个核心规则：

- 端口扫描检测：同一源 IP 在时间窗口内访问同一目标的多个不同端口。
- SYN Flood 检测：同一源 IP 在时间窗口内向同一目标发送大量 TCP SYN 且不含 ACK 的包。
- ICMP Flood 检测：同一源 IP 在时间窗口内向同一目标发送大量 ICMP 包。
- 敏感端口访问检测：检测 FTP、SSH、Telnet、SMB、RDP、MySQL 等常见敏感端口访问。
- 黑名单 IP 检测：检测源 IP 或目标 IP 是否命中 `config/blacklist.txt`。

## 告警中心与报告

pcap 导入时会同步运行检测引擎，生成的告警会写入 SQLite。进入“告警中心”可以按等级筛选、关键字搜索、查看详情、确认或忽略告警，并导出 CSV。

进入“报告导出”可以导出：

- HTML 检测报告
- 告警 CSV
- 告警 JSON

如果 Windows 临时目录权限导致 pytest 无法创建临时文件，可使用项目内临时目录运行：

```powershell
.conda\Lightweight-IDS\python.exe -m pytest --basetemp .test_tmp -o cache_dir=.test_cache
```

## 规则管理

进入“规则管理”可以：

- 启用或禁用规则
- 修改阈值
- 修改时间窗口
- 编辑规则说明
- 恢复默认规则
- 管理 `config/blacklist.txt` 黑名单 IP

保存后的规则会影响后续 pcap 导入和实时抓包检测。

## 仪表盘统计

仪表盘会从 SQLite 读取统计数据并展示：

- 已处理数据包数量
- 告警总数
- 高危告警数量
- 协议分布
- 告警等级分布
- Top 源 IP
- Top 目标端口

## 实时抓包

进入“流量监控”，点击“刷新网卡”后选择网卡，再点击“开始抓包”。Windows 下实时抓包通常需要：

- 安装 Npcap
- 允许 Scapy 访问网卡
- 必要时以管理员权限运行

实时抓包只被动接收本机网卡流量，不会扫描或攻击任何目标。

## Windows 抓包说明

实时抓包属于后续阶段功能。Windows 下通常需要安装 Npcap，并可能需要管理员权限。本项目优先支持离线 pcap 文件分析，避免对公网目标进行任何扫描或攻击。

## 课程项目声明

本项目仅用于教学、实验和防御性检测，不用于任何未授权测试、扫描或攻击。
