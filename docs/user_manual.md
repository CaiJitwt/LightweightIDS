# Lightweight IDS User Manual

## Start The Application

Recommended:

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

With an already activated Python 3.11+ environment:

```powershell
python main.py
```

Avoid running the project with a system Python that does not have PySide6, Scapy and the other dependencies installed.

## Traffic Monitor

Use `Import pcap` to select a local `.pcap`, `.pcapng` or `.cap` file. The application parses packets, saves them to SQLite, applies enabled detection rules and displays generated alerts.

Use `Import decrypted HTTP log` only for local JSONL or CSV records that already contain plaintext HTTP data from an authorized lab or defensive source. This enables SQL injection, XSS, suspicious HTTP, malicious command and advanced Web attack rules to inspect HTTP content offline.

For live capture, click `Refresh interfaces`, choose an interface or the default interface, and click `Start capture`. On Windows, install Npcap and run as administrator if capture fails.

## Alert Center

The Alert Center lists generated alerts with severity, type, source, destination, protocol, description, evidence and status. Use the available actions to review, ignore or update alert status.

## Rule Management

Built-in rules can be enabled or disabled, and their thresholds and time windows can be edited. Custom rules support optional protocol, source IP, destination IP, source port, destination port and keyword conditions. Empty fields mean no restriction.

Blacklist entries are one IP address per line. Save changes before importing new traffic or starting live capture.

## Reports

Use the Reports page to export detection results as HTML, CSV or JSON. Reports summarize packets, alerts, severity distribution, alert types and key traffic statistics.

## Settings

选中告警后，`Related packets` 会按规则时间窗口列出关联数据包。主机扫描、端口扫描、泛洪和横向移动告警可能对应多个数据包。右键数据包可将源 IP、目标 IP、源端口或目标端口加入 enforced blocklist。

Windows 下 enforced blocklist 会尝试创建 Windows Firewall 规则，通常需要管理员权限。只有状态为 `Active` 才表示操作系统已经接受规则；`Failed` 或 `Unsupported` 不能视为已经阻断。离线 pcap 只能分析，不能拒绝历史流量。

## 主机分析

`Host Explorer` 汇总 packets、alerts、baselines 和 assets 中出现的主机。左侧列表展示风险分数、资产重要性、数据包数量、告警数量和最后活动时间；右侧可查看：

- `Overview`：资产属性、风险原因、入站/出站流量、常见协议和端口。
- `Connections`：通信对端、方向、协议、端口和数据包数量。
- `Alerts`：该 IP 作为源或目标时关联的告警。
- `Timeline`：按时间合并的数据包活动和告警事件。

在 Dashboard 的 `High-risk hosts` 表格中双击主机，可直接跳转到 Host Explorer。`Create investigation` 会以当前主机和相关告警创建调查记录。

## 调查管理

`Investigations` 用于保留人工核实过程和证据：

- 调查状态包括 `Open`、`Monitoring` 和 `Closed`。
- 优先级包括 `LOW`、`MEDIUM`、`HIGH` 和 `CRITICAL`。
- Alert Center 的 `Add to investigation` 可把选中告警加入现有调查或新建调查。
- 调查证据保存告警快照；删除原告警或重置统计后，快照仍然保留。
- `Export HTML` 可导出当前调查、备注和证据列表。

## 资产管理

`Assets` 用于为 IP 设置显示名称、角色、重要性和备注。角色使用固定选项，重要性范围为 0–100。

高重要性资产会参与 Dashboard 主机风险评分。新启动的导入或实时抓包也会读取资产重要性，并通过现有降噪模块对高价值资产相关告警进行等级提升。资产不会自动加入白名单。

## 规则管理

规则管理页面包含内置规则、自定义规则和黑名单。

内置规则支持：

- 启用或禁用。
- 修改阈值。
- 修改时间窗口。
- 恢复默认规则。

自定义规则支持：

- 规则名称。
- 告警等级。
- 是否启用。
- 协议选择。
- 源 IP、目标 IP。
- 源端口、目标端口。
- 关键词。
- 描述。

空条件表示不限制该字段。端口输入为 `0` 时表示不限端口。

## 报告导出

报告导出页面可将告警导出为 CSV 或 JSON，用于课程报告、截图说明和后续分析。

## 常见问题

### 提示缺少 PySide6

请确认使用的是项目 Conda 环境：

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

### 实时抓包没有数据

在 Windows 上实时抓包通常需要安装 Npcap，并可能需要以管理员权限运行终端。

### 新规则没有出现在规则管理页

重新启动程序或点击恢复默认规则。数据库初始化会自动补齐新增规则，但不会覆盖用户已经调整过的阈值和启用状态。
