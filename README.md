# Lightweight IDS

## Course-Level AI Flow Anomaly Detection

Lightweight IDS includes a lightweight flow anomaly module for local coursework experiments. `FlowFeatureExtractor` aggregates `PacketRecord` objects by source IP, destination IP, and time window, then produces features such as packet count, byte count, destination diversity, SYN/ICMP/DNS counts, sensitive-port count, and HTTP indicator count.

`IsolationForestFlowDetector` uses scikit-learn `IsolationForest` when it is already installed. If scikit-learn is unavailable, it automatically falls back to the built-in `SimpleAnomalyDetector` plus deterministic flow heuristics, so the project remains testable without external network access or extra downloads. Models can be saved to and loaded from `data/models/flow_anomaly.pkl`.

The `ML_FLOW_ANOMALY` rule emits `ML_ANOMALY` alerts with a score and top reasons. This is a defensive, explainable course feature, not a replacement for rule review or authorized lab validation.

## Authorized Decrypted HTTPS Analysis

Lightweight IDS can import local JSONL or CSV logs that already contain decrypted HTTP request data from an authorized lab environment. This workflow is intended for defensive coursework, controlled experiments, and traffic the user has permission to inspect.

The project does not install certificates, does not perform unauthorized man-in-the-middle interception, and does not actively access public targets. The `Import decrypted HTTP log` workflow only reads a local file and converts each record into an HTTP `PacketRecord` so existing application-layer rules such as `SQL_INJECTION`, `XSS`, `HTTP_SUSPICIOUS`, and `MALICIOUS_COMMAND` can run offline.

Normal pcap files that contain encrypted HTTPS payloads cannot be directly inspected for SQL injection or XSS content. For HTTPS content detection, provide logs from an authorized decrypted source, such as a course lab TLS proxy/exporter or another system where you are explicitly permitted to inspect the plaintext HTTP data.

轻量级网络入侵检测系统课程项目。项目使用 Python 3.11、PySide6、Scapy 和 SQLite，实现本地 pcap 离线检测、规则匹配、告警展示、日志保存和报告导出；实时抓包能力已预留并实现基础入口。

本项目只用于教学、实验和防御性检测，不包含真实攻击利用代码，不对公网目标进行扫描或攻击。测试应基于本地 pcap 文件、实验环境流量或模拟数据。

## 功能特性

- PySide6 桌面 GUI：左侧导航、仪表盘、流量监控、告警中心、规则管理、报告导出、系统设置。
- pcap 离线分析：使用 Scapy 读取 `.pcap`、`.pcapng`、`.cap` 文件。
- 数据包标准化：转换为统一的 `PacketRecord`，表格展示时间、源/目标 IP、协议、端口、长度和摘要。
- 协议解析：支持 TCP、UDP、ICMP、DNS、HTTP 等基础字段。
- 检测引擎：`DetectionEngine` 加载规则并维护告警冷却，规则继承 `RuleBase`。
- 核心规则：端口扫描、SYN Flood、ICMP Flood、敏感端口访问、黑名单 IP。
- 扩展规则：暴力破解、DNS 异常、HTTP 可疑请求，以及 SQL/XSS/异常外联等课程展示规则。
- SQLite 持久化：保存数据包、告警、规则和设置。
- 管理能力：规则启用/禁用、阈值和时间窗口修改、黑名单维护、自定义规则。
- 报告导出：HTML 检测报告、告警 CSV、告警 JSON。
- 单元测试：覆盖模型、解析、规则、检测引擎、数据库、报告导出等主链路。

## 技术栈

- Python 3.11+
- PySide6
- Scapy
- SQLite
- YAML 配置：PyYAML
- 日志：Python `logging`
- 测试：pytest
- 打包预留：PyInstaller

## 安装方法

建议使用项目内 Conda 环境：

```powershell
.\.conda\Lightweight-IDS\python.exe -m pip install -r requirements.txt
```

也可以使用任意 Python 3.11+ 环境：

```powershell
python -m pip install -r requirements.txt
```

## 运行方法

在项目根目录运行：

```powershell
.\.conda\Lightweight-IDS\python.exe main.py
```

如果使用系统 Python：

```powershell
python main.py
```

首次启动会自动初始化数据库：

```text
data/lightweight_ids.db
```

## Windows 抓包环境说明

离线 pcap 分析不需要管理员权限。实时抓包依赖本机网卡权限，Windows 下通常需要安装 [Npcap](https://npcap.com/) 并可能需要以管理员身份运行。

实时抓包只被动接收本机网卡流量，不会扫描、攻击或主动访问任何目标。

## 使用步骤

1. 启动程序，进入主窗口。
2. 打开“流量监控”，点击“Import pcap”导入本地 pcap 文件。
3. 程序会逐包解析、表格展示、运行检测规则，并将数据包和告警写入 SQLite。
4. 打开“告警中心”，按等级筛选、搜索、查看详情、确认或忽略告警。
5. 打开“规则管理”，启用/禁用规则，修改阈值和时间窗口，维护黑名单 IP。
6. 打开“报告导出”，导出 HTML、CSV 或 JSON 报告。

## 目录结构

```text
lightweight-ids/
├── main.py
├── requirements.txt
├── config/              # 默认配置、规则配置、黑名单
├── app/                 # 应用入口和常量
├── capture/             # pcap 加载、实时抓包、网卡管理
├── parser/              # Scapy 数据包解析和特征提取
├── detection/           # 检测引擎、规则基类、窗口计数器、规则实现
├── models/              # PacketRecord、AlertRecord、RuleRecord 等模型
├── storage/             # SQLite 初始化和仓储层
├── ui/                  # PySide6 主窗口、页面和表格组件
├── report/              # HTML/CSV/JSON 报告导出
├── utils/               # 配置、日志、时间、IP 工具
├── tests/               # 单元测试
├── sample_data/         # 示例说明和示例告警
└── docs/                # 项目计划、系统设计、用户手册、测试报告
```

## 检测规则说明

- `PORT_SCAN`：同一源 IP 在时间窗口内访问同一目标的不同目标端口数达到阈值时告警，默认阈值 20、窗口 10 秒、等级 HIGH。
- `SYN_FLOOD`：同一源 IP 在时间窗口内向同一目标发送大量 TCP SYN 且不含 ACK 的包时告警，默认阈值 100、窗口 10 秒、等级 HIGH。
- `ICMP_FLOOD`：同一源 IP 在时间窗口内向同一目标发送大量 ICMP 包时告警，默认阈值 50、窗口 10 秒、等级 MEDIUM。
- `SENSITIVE_PORT`：访问 21、22、23、25、445、1433、3306、3389、6379、9200 等敏感端口时告警，默认等级 MEDIUM。
- `BLACKLIST_IP`：源 IP 或目标 IP 命中 `config/blacklist.txt` 时告警，默认等级 HIGH。

黑名单文件每行一个 IP，支持空行和 `#` 注释。

## 报告导出说明

HTML 报告包含检测时间、数据包总数、告警总数、各等级告警数量、各类型告警数量、Top 源 IP、Top 目标端口、详细告警列表和简要安全建议。

告警中心和报告页面还支持导出 CSV 和 JSON，便于课程答辩、复盘和二次分析。

## 测试

直接运行：

```powershell
.\.conda\Lightweight-IDS\python.exe -m pytest
```

当前测试配置会使用项目内 `.test_tmp` 临时目录，避免 Windows 受限环境无法访问系统临时目录。

最近一次验证结果：

```text
46 passed
```

## 常见问题

**缺少 PySide6 或 Scapy 怎么办？**

确认当前解释器是安装依赖的 Python，然后重新运行 `python -m pip install -r requirements.txt`。

**导入 pcap 后没有告警是否正常？**

正常。告警取决于 pcap 中是否存在命中规则的行为，可以用测试构造数据验证规则触发。

**实时抓包无法启动怎么办？**

在 Windows 上确认已安装 Npcap，并尝试使用管理员权限启动；也可以先使用离线 pcap 完成课程展示。

**项目会不会产生攻击流量？**

不会。项目的核心流程是读取本地文件或被动接收本机流量，进行防御性检测和展示。

## 课程项目声明

本项目仅用于教学、实验和防御性检测，不用于任何未授权测试、扫描、攻击或入侵活动。使用者应只分析自己有权限处理的 pcap 文件、实验环境流量或模拟数据。
