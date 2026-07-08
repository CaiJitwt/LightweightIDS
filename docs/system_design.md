# 系统设计

系统按职责划分为捕获、解析、检测、存储、界面和报告模块。

- `capture`：pcap 导入和实时抓包。
- `parser`：Scapy 数据包解析和协议识别。
- `detection`：检测引擎、内置规则和自定义规则。
- `storage`：SQLite 初始化和数据访问。
- `ui`：PySide6 桌面界面。
- `report`：HTML、CSV、JSON 报告导出。

## 离线检测链路

1. “流量监控”选择本地 pcap 文件。
2. 后台线程使用 Scapy 逐包解析为 `PacketRecord`。
3. `DetectionEngine` 对每个数据包运行内置规则和自定义规则。
4. `PacketRecord` 和 `AlertRecord` 分别写入 SQLite。
5. “告警中心”和“报告导出”从 SQLite 读取结果。

## 实时检测链路

1. “流量监控”刷新并选择网卡。
2. `LiveCapture` 使用 Scapy 被动抓取本机网卡流量。
3. 后台线程将原始包解析为 `PacketRecord`。
4. `DetectionEngine` 使用 SQLite 中当前规则配置进行检测。
5. 流量记录和告警写入 SQLite，界面同步显示数据包表格。

## 规则管理链路

1. “规则管理”从 SQLite 的 `rules` 表加载内置规则配置。
2. 用户修改启用状态、阈值、时间窗口和说明。
3. 保存后写回 SQLite。
4. 后续 pcap 导入和实时抓包重新读取规则配置。

## 自定义规则链路

1. “规则管理”中的自定义规则写入 SQLite 的 `custom_rules` 表。
2. pcap 导入或实时抓包开始时读取自定义规则。
3. `CustomRule` 使用协议、IP、端口和关键字条件做字段匹配。
4. 命中后生成 `CUSTOM_RULE` 告警。
