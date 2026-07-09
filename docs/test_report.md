# Lightweight IDS 测试报告

## 测试环境

- 操作系统：Windows
- Python：项目内 Conda 环境 Python 3.11.15
- 测试框架：pytest
- 主要依赖：PySide6、Scapy、PyYAML

## 测试命令

项目已提供 `pytest.ini`，默认使用项目内 `.test_tmp` 临时目录：

```powershell
.\.conda\Lightweight-IDS\python.exe -m pytest
```

## 最近一次测试结果

```text
46 passed
```

## 覆盖范围

- 数据模型校验：`PacketRecord`、`AlertRecord`、`RuleRecord`。
- SQLite 初始化：`packets`、`alerts`、`rules`、`settings` 等表和默认规则。
- pcap 加载：Scapy `PcapReader` 读取本地 pcap。
- 数据包解析：TCP、UDP、ICMP、DNS、HTTP 等基础字段提取。
- 检测引擎：规则调用、启用禁用、阈值更新、告警冷却。
- 核心规则：端口扫描、SYN Flood、ICMP Flood、敏感端口、黑名单。
- 扩展规则：暴力破解、DNS 异常、HTTP 可疑请求、SQL/XSS、异常外联等。
- 告警仓储：插入、查询、筛选、状态更新。
- 报告导出：HTML、CSV、JSON。

## 手动验收建议

1. 启动 `python main.py`，确认主窗口和左侧导航可打开。
2. 导入本地 pcap，确认流量表格出现数据包。
3. 导入包含规则命中行为的测试 pcap 或模拟数据，确认告警写入告警中心。
4. 在规则管理页修改阈值、启用状态和黑名单，重新导入流量验证配置生效。
5. 在报告导出页生成 HTML 报告，确认统计和告警列表完整。

## 已知限制

- 实时抓包依赖本机网卡权限、Npcap 和运行权限；离线 pcap 检测是当前最稳定的课程展示路径。
- 扩展检测规则以轻量级启发式匹配为主，适合课程展示，不替代生产级 IDS。
- 项目不包含攻击利用脚本，不会主动扫描或攻击任何目标。
