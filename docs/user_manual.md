# Lightweight IDS 用户手册

## 启动方式

推荐使用项目内的 Conda 环境：

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

如果使用已激活的环境，也可以运行：

```powershell
python main.py
```

注意：不要用系统全局 Python 运行项目，否则可能找不到 PySide6 或 Scapy。

## 仪表盘

仪表盘用于查看整体安全态势，包括：

- 已处理数据包数量。
- 告警总数。
- 高危告警数量。
- 检测状态。
- 协议分布、告警等级、Top 源 IP、Top 目标端口。
- 攻击链阶段统计。
- 异常评分趋势。
- 攻击链时间线。

点击 `Refresh statistics` 可手动刷新统计结果。

## 流量监控

流量监控页面用于导入 pcap 文件或进行实时抓包。导入后系统会解析数据包，并把 `PacketRecord` 展示到表格中。如果启用了实时检测，系统会同时生成告警。

常见字段包括：

- 时间。
- 源 IP 和目标 IP。
- 源端口和目标端口。
- 协议。
- 长度。
- TCP flags。
- DNS 查询。
- HTTP 方法、Host 和路径。
- payload 摘要。

## 告警中心

告警中心支持：

- 按等级筛选告警。
- 按规则、IP、描述或证据搜索告警。
- 查看告警详情。
- 将告警标记为 confirmed 或 ignored。
- 导出当前告警列表为 CSV。
- 查看按源 IP 关联出的攻击链视图。

攻击链视图会展示源 IP、风险分数、攻击阶段和关联告警数量。

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
