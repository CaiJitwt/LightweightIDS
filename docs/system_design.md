# 系统设计

系统按职责划分为捕获、解析、检测、存储、界面和报告模块。

- `capture`：pcap 导入和实时抓包接口。
- `parser`：协议解析和特征提取。
- `detection`：规则引擎和检测规则。当前包含端口扫描、SYN Flood、ICMP Flood、敏感端口、黑名单 IP 规则。
- `storage`：SQLite 初始化和数据访问。
- `ui`：PySide6 桌面界面。
- `report`：HTML、CSV、JSON 报告导出。

当前离线检测链路：

1. “流量监控”选择本地 pcap 文件。
2. 后台线程使用 Scapy 逐包解析为 `PacketRecord`。
3. `DetectionEngine` 对每个数据包运行 5 个核心规则。
4. `PacketRecord` 和 `AlertRecord` 分别写入 SQLite。
5. “告警中心”和“报告导出”从 SQLite 读取结果。

实时检测链路：

1. “流量监控”刷新并选择网卡。
2. `LiveCapture` 使用 Scapy 被动抓取本机网卡流量。
3. 后台线程将原始包解析为 `PacketRecord`。
4. `DetectionEngine` 使用 SQLite 中当前规则配置进行检测。
5. 流量记录和告警写入 SQLite，界面同步显示数据包表格。

规则管理链路：

1. “规则管理”从 SQLite 的 `rules` 表加载规则。
2. 用户修改启用状态、阈值、时间窗口和说明。
3. 保存后写回 SQLite。
4. 后续 pcap 导入和实时抓包重新读取规则配置。
