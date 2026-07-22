# Lightweight IDS 用户手册

[English](user_manual.md) | [简体中文](user_manual.zh-CN.md) | [文档索引](README.zh-CN.md)

## 1. 选择界面

Lightweight IDS 提供两套受支持界面，默认使用同一个 SQLite 数据库。

### 现代分析工作台

```powershell
python modern_main.py
```

适合使用浏览器分析工作流，包括丰富图表、实时抓包、pcap 导入、主机分析、网络拓扑、Windows 安全事件、端点状态和可选 LLM 防御建议。

启动器会自动选择两个可用的回环端口，启动本地 API 和前端，并输出两个地址。如果页面提示 `Offline preview`，请重新启动 `modern_main.py`；预览数据不是项目中的持久化数据。

### 经典 PySide6 桌面端

```powershell
python main.py
```

适合使用原生 Qt 工作流、确定性演示数据、授权解密 HTTP 日志导入、自定义规则编辑、强制黑名单和调查证据快照。

## 2. 首次启动与数据

默认数据库会自动创建在：

```text
data/lightweight_ids.db
```

数据库迁移采用增量方式并保留已有记录。缺失的内置规则会自动补齐，但不会覆盖用户已经保存的阈值和启用状态。

## 3. Traffic Monitor

### 导入抓包文件

从界面选择 `.pcap`、`.pcapng` 或 `.cap` 文件。数据包会经过解析、启用规则检测，并在开启保存时写入数据库。告警由 Detection Engine 正常生成，不会直接插入演示告警。

现代工作台使用浏览器文件选择器，并把文件交给本地 API；经典桌面端使用系统原生文件选择器。

### 实时抓包

1. Windows 上安装 Npcap。
2. 使用具备抓包权限的终端启动应用。
3. 刷新并选择网络接口。
4. 可选填写并验证抓包/显示过滤器。
5. 点击 `Start capture`。
6. 根据需要使用 Pause、Resume 或 Stop。

浏览器自身不会抓包，实际抓包由 `modern_main.py` 启动的本地 Python 服务完成。

最新数据包显示在最前面。选择数据包后可以查看完整的已存储元数据和摘要。

### 演示数据

使用以下命令生成时间确定的演示 pcap：

```powershell
python -m scripts.generate_demo_pcap
```

然后导入 `sample_data/demo_attack_chain.pcap`。经典桌面端的 `Load demo data` 会在文件缺失时自动生成。

需要从虚拟机向宿主机进行实时演示时，请参考 [HTTP 告警演示实验室](../demo_http_lab/README.md)。在连接虚拟机的网卡上使用 `tcp.dstport == 8080` 启动抓包，运行 `python -m demo_http_lab.main`，再从虚拟机打开终端打印的私网地址。默认课堂模式无需令牌。样本会经过实时抓包和 Detection Engine，接收器不会执行、持久化或转发内容。

### 授权解密 HTTP 日志

经典桌面端可以导入已经包含明文 HTTP 请求的授权 JSONL 或 CSV 记录。该功能适用于本人控制的实验室代理或应用网关导出。详细格式见 [HTTPS 实验流程](https_lab_workflow.md)。

程序不会从原始 pcap 中解密 HTTPS 流量。

## 4. Dashboard

Dashboard 汇总数据包数量、未处理告警、高风险主机、严重等级分布、流量/告警趋势和告警检测率。现代 Dashboard 开启 Auto-refresh 后会定时刷新。

`Reset statistics` 会清除：

- 数据包和实时数据包缓冲；
- 告警和告警计数；
- 行为基线记录；
- Windows 安全事件；
- pcap 导入和抓包会话计数；
- Reports 和 Event Timeline 中的运行期内容。

资产、调查和调查证据快照会被保留。

## 5. Alert Center

选择告警后可以查看严重等级、规则、通信端点、描述、证据和人工处理状态。关联数据包会根据告警通信端点和规则时间窗口匹配，因此扫描、泛洪和横向移动等聚合告警可能对应多个数据包。

选择数据包可以查看完整存储元数据。应在核实证据后再确认或忽略告警。状态修改只影响分析工作流，不会改写原始数据包。

经典桌面端可以把告警加入调查，也可以通过数据包右键菜单将源 IP、目标 IP、源端口或目标端口加入强制黑名单。

## 6. Host Explorer 与 Assets

Host Explorer 合并出现在数据包、告警、行为基线和资产中的 IP，并提供：

- 主机综合风险和评分原因；
- 入站与出站活动；
- 通信对端、协议、端口和数据包数量；
- 该主机作为源或目标时的告警；
- 合并后的主机时间线。

Assets 可以为唯一 IP 设置显示名称、受控角色、0 到 100 的重要性和备注。资产重要性会影响人工处置优先级和主机风险评分，但不会自动创建白名单。现代和经典界面都会把资产修改持久化到共享 SQLite 数据库；编辑时不能修改资产 IP。

## 7. Rule Management

内置规则可以启用或禁用。阈值和时间窗口会持久化到 SQLite，并对之后的导入和抓包会话生效；已有告警不会自动重新计算。

CPU 和 GPU 长期高负载规则默认阈值为 90%，时间窗口为 300 秒。它们用于提示可能存在挖矿或恶意程序，但正常的高强度工作也可能触发。GPU 监控需要受支持的 NVIDIA `nvidia-smi` 遥测。

经典桌面端还支持自定义规则，可设置协议、源/目标 IP、源/目标端口、关键词、严重等级和描述。空字段表示不限制，端口 `0` 表示任意端口。

## 8. 黑名单与执行状态

经典 Rule Management 会保存结构化 IP 和端口黑名单。Alert Center 的关联数据包菜单可以快速添加字段。

Windows 上程序会尝试创建对应的 Windows 防火墙规则，通常需要管理员权限。

- `Active`：操作系统已经接受防火墙规则。
- `Failed`：条目已经保存，但执行失败。
- `Unsupported`：当前平台不支持自动执行。

离线 pcap 代表历史流量，无法被事后阻断。详细说明见 [防护工作流](protection_workflow.md)。

## 9. Investigations 与 Reports

调查记录包含标题、主机、状态、优先级、摘要和备注。现代界面已经通过本地 API v6 实现持久化的新建、读取、编辑和删除。经典调查证据以快照形式保存，因此删除原告警或重置运行统计后仍然存在；证据添加/移除和 HTML 导出仍由经典桌面端提供。

Reports 用于导出持久化告警。现代 Reports 支持 HTML、CSV 和 JSON；经典报告还会汇总数据包和告警统计。重置后显示空数据属于正常行为，不会再由演示告警填充。

## 10. Event Timeline 与 Network Topology

现代 Event Timeline 合并持久化数据包、告警和 Windows 安全事件。重置统计会清除这些运行期记录。

Network Topology 根据当前已存储或实时抓包的数据包连接生成节点和边，不依赖演示数据。关闭数据包持久化时，活动抓包会话仍可显示内存中的实时连接。

## 11. Security Events 与 Endpoint Security

现代工作台可以监控指定 Windows 安全事件通道、显示相关事件，并根据已配置规则生成端点告警。可在 Security Events 页面使用 Start、Stop 和 Refresh。

Endpoint Security 提供只读主机状态、进程清单和文件完整性基线/扫描。System Health 显示本地 API、传感器、存储、CPU、内存、磁盘和受支持 GPU 遥测。

这些模块使用用户态操作系统接口，不是内核模块。

## 12. Settings、LLM 与个性化

Settings 可以调整数据包持久化、实时检测、告警冷却、最低告警等级、安全事件监控、主题和字号。

现代 LLM 面板可以配置 OpenAI 兼容 Base URL、模型和 API Key。Base URL 与模型保存在 SQLite 中；Windows 上 API Key 使用当前用户的 DPAPI 加密，不会返回浏览器，页面只显示是否已经配置。只有分析人员主动点击 `Generate defense guidance` 时才会发送告警数据，并可选择中文或英文回答。

现代主题、字号、组件外观、壁纸和悬浮宠物设置通过本地 API 持久化。配置保存在 SQLite 中，上传的图片复制到 `<数据库目录>/personalization/modern`（默认是 `data/personalization/modern`），因此更换浏览器端口或重启应用后仍可恢复；浏览器存储仅作为离线缓存。经典桌面端使用其独立的受管理个性化资源目录。

## 13. 常见问题

### Local API unavailable

停止旧启动器或 API 进程，然后重新运行：

```powershell
python modern_main.py
```

默认情况下启动器会自动选择可用端口。只有需要固定地址时才使用 `--api-port` 和 `--frontend-port`。

### 实时抓包没有数据

检查 Npcap、网络接口、运行权限和过滤器语法。可以先使用空过滤器测试。VPN、回环和虚拟机流量可能经过与普通 Ethernet/Wi-Fi 不同的接口。

### 调整规则后旧告警没有变化

规则修改只作用于之后的分析。调整阈值后需要重新导入 pcap 或启动新抓包。

### GPU telemetry unavailable

当 `nvidia-smi` 无法提供利用率时，GPU 规则会保持静默，CPU 监控不受影响。

### 黑名单没有拒绝流量

确认条目状态为 `Active`。如果状态为 `Failed`，请使用管理员权限重试并查看 Windows 防火墙返回的错误。

## 14. 安全边界

请仅在获得授权的范围内使用本项目。TLS 告警只代表元数据或指纹风险，不包含解密后的 HTTPS 正文。所有检测结果都需要人工核实，单条告警不能直接证明主机已被攻陷。
