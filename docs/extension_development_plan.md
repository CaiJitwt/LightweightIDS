# IDS Extension Development Document

## 1. 项目背景


这是一个基于 **PySide6 + SQLite** 的轻量级 IDS 项目。现阶段需要基于 `docs/extension_ideas.md` 中的扩展设想继续开发项目功能。

本轮开发优先实现以下功能：

1. Host Risk Scoring，主机风险评分
2. Demo Dataset + One-click Demo，演示数据集与一键演示
3. Alert Trend Analysis，告警趋势分析
4. Rule Effectiveness Feedback，规则效果反馈，作为同轮加分项

开发过程中应保持 UI 文案为英文，优先沿用现有代码风格，不引入重型新依赖。`Scapy` 已经在 `requirements.txt` 中可用，可以用于构造演示 PCAP 数据。

---

## 2. 开发前需要阅读的文件

实现前应先阅读以下入口文件，理解现有架构、数据流、规则检测逻辑和 UI 组织方式：

```text
docs/extension_ideas.md
storage/repositories.py
storage/migrations.py
detection/analysis/attack_chain.py
detection/analysis/false_positive.py
ui/dashboard_page.py
ui/packet_page.py
ui/rule_page.py
ui/widgets/chart_widget.py
parser/packet_parser.py
detection/rules/sql_injection.py
detection/rules/xss.py
detection/rules/malicious_command.py
detection/rules/tls_fingerprint.py
detection/rules/host_scan.py
detection/rules/lateral_movement.py
```

---

# 3. 功能一：Host Risk Scoring

## 3.1 功能目标

新增主机风险评分功能，用于根据告警严重等级、攻击链、baseline 偏离情况和资产重要性，对不同源主机进行综合风险排序。

Dashboard 页面应新增一个 **High-risk hosts** 区域，直观展示高风险主机列表。

---

## 3.2 新增模块

新增文件：

```text
detection/analysis/host_risk.py
```

---

## 3.3 数据结构设计

定义 `HostRiskBreakdown` dataclass，至少包含以下字段：

```python
source_ip: str
score: float
severity_score: float
chain_score: float
baseline_score: float
asset_score: float
reasons: list[str]
```

字段含义如下：

| 字段               | 含义                |
| ---------------- | ----------------- |
| `source_ip`      | 源主机 IP            |
| `score`          | 综合风险评分，最高 100     |
| `severity_score` | 告警严重等级得分          |
| `chain_score`    | 攻击链相关得分           |
| `baseline_score` | baseline 活跃度或偏离得分 |
| `asset_score`    | 资产重要性得分           |
| `reasons`        | 风险原因说明            |

---

## 3.4 HostRiskScorer 设计

实现 `HostRiskScorer` 类，输入包括：

```python
alerts
attack_chains
baseline_records
asset_importance: dict[str, float] | None = None
```

其中：

* `alerts`：已有告警记录
* `attack_chains`：攻击链分析结果
* `baseline_records`：baseline 相关记录
* `asset_importance`：可选资产重要性配置，默认为空字典

评分应按 `src_ip` 汇总。

---

## 3.5 评分规则

综合评分上限为 100，建议权重如下：

| 评分来源              |  权重 |
| ----------------- | --: |
| 告警严重等级            | 40% |
| 攻击链               | 30% |
| baseline 活跃度 / 偏离 | 20% |
| 资产重要性             | 10% |

最终得分建议形式：

```text
score = severity_score * 0.4
      + chain_score * 0.3
      + baseline_score * 0.2
      + asset_score * 0.1
```

然后限制在 `0 ~ 100` 范围内。

---

## 3.6 攻击链复用要求

攻击链评分必须复用现有：

```python
AttackChainAnalyzer.analyze()
```

不要重复实现攻击阶段排序逻辑，避免与现有攻击链分析模块产生不一致。

---

## 3.7 Dashboard UI 要求

在 `ui/dashboard_page.py` 中新增 **High-risk hosts** 表格。

表格列建议如下：

| Column   | Description            |
| -------- | ---------------------- |
| Host     | Source IP              |
| Score    | Final risk score       |
| Severity | Alert severity score   |
| Chain    | Attack chain score     |
| Baseline | Baseline score         |
| Asset    | Asset importance score |
| Reasons  | Explanation            |

UI 文案必须使用英文。

对于 `Reasons` 这类长文本，应添加 tooltip，避免表格显示拥挤。

---

## 3.8 资产重要性限制

本轮开发不新增资产表。

`asset_importance` 暂时采用：

1. 可选配置传入；或
2. 默认空字典。

未配置资产重要性的主机，`asset_score` 可以默认为 0。

---

# 4. 功能二：Demo Dataset + One-click Demo

## 4.1 功能目标

新增确定性的演示 PCAP 数据，并在 Packet 页面提供一键导入按钮，方便演示 IDS 的完整检测链路。

该功能应展示从 PCAP 导入、包解析、规则检测、告警生成、攻击链分析到 Dashboard 展示的完整流程。

---

## 4.2 新增脚本

新增文件：

```text
scripts/generate_demo_pcap.py
```

脚本输出文件：

```text
sample_data/demo_attack_chain.pcap
```

---

## 4.3 PCAP 生成要求

使用 `Scapy` 构造确定性的演示流量。

必须显式设置：

```python
packet.time
```

确保导入后时间线稳定，趋势分析结果稳定，演示过程可复现。

---

## 4.4 必须触发的规则

演示流量必须能触发现有规则中的多个规则，包括但不限于：

```text
HOST_SCAN
SQL_INJECTION
MALICIOUS_COMMAND
TLS_FINGERPRINT
LATERAL_MOVEMENT
ADMIN_SHARE_ACCESS
```

至少应覆盖常见攻击链场景。

---

## 4.5 Host Scan 与攻击链连续性要求

Host scan 包数量必须超过默认阈值，确保能够触发 `HOST_SCAN` 告警。

同时需要注意：

最后一个扫描目标应与后续 SQL Injection、Command Injection、TLS Fingerprint 或 Admin Share 相关流量保持：

```text
same src_ip + same dst_ip
```

这样可以帮助 `AttackChainAnalyzer` 形成连续攻击链，而不是产生彼此孤立的告警。

---

## 4.6 Packet Page UI 要求

在：

```text
ui/packet_page.py
```

新增按钮：

```text
Load demo data
```

按钮点击后调用现有导入逻辑：

```python
start_import(PROJECT_ROOT / "sample_data" / "demo_attack_chain.pcap")
```

---

## 4.7 PCAP 文件不存在时的处理

如果：

```text
sample_data/demo_attack_chain.pcap
```

不存在，应满足以下处理方式之一：

1. 给出清晰的错误提示；或
2. 自动调用 `scripts/generate_demo_pcap.py` 生成一次。

推荐优先自动生成一次，以提升演示便利性。

---

## 4.8 禁止绕过检测引擎

不得直接向数据库插入假告警。

演示数据必须通过真实流程产生告警：

```text
PCAP -> PcapLoader -> PacketParser -> DetectionEngine -> Alerts
```

这样可以保证演示结果能够体现实际 IDS 检测能力。

---

# 5. 功能三：Alert Trend Analysis

## 5.1 功能目标

新增告警趋势分析能力，支持 Dashboard 展示最近一段时间内的告警数量变化，并标记异常峰值。

---

## 5.2 Repository 层扩展

在 `AlertRepository` 中新增按时间分桶查询方法，例如：

```python
count_by_time_bucket(bucket="hour", limit=24)
```

并可选支持：

```python
bucket="day"
```

建议返回结构包含：

```python
bucket_start
count
```

其中：

* `bucket_start`：时间桶起始时间
* `count`：该时间桶内告警数量

---

## 5.3 新增分析模块

新增文件：

```text
detection/analysis/alert_trend.py
```

该模块负责：

1. 获取或接收时间分桶后的告警数据；
2. 计算历史均值；
3. 计算历史标准差；
4. 标记 spike 异常桶。

---

## 5.4 Spike 判定规则

若当前桶告警数量满足：

```text
current_count > historical_mean + 2 * historical_std
```

则标记为异常峰值。

需要注意：

* 历史数据不足时，应避免误报；
* 标准差为 0 时，应合理处理；
* 不应因为空数据导致 Dashboard 报错。

---

## 5.5 Dashboard UI 要求

在 `ui/dashboard_page.py` 中新增：

```text
Alert trend
```

区域。

展示内容包括：

1. 最近 24 小时的告警量；或
2. 最近若干天的告警量。

异常桶应通过文本或样式提示，例如：

```text
Spike
```

可以扩展现有：

```text
ui/widgets/chart_widget.py
```

也可以新增轻量级 `TrendWidget`。

要求：

* 不破坏现有图表调用方式；
* UI 文案保持英文；
* 空数据时展示合理提示，而不是报错。

---

# 6. 功能四：Rule Effectiveness Feedback

## 6.1 功能目标

新增规则效果反馈功能，用于统计每条规则产生的告警数量、确认数量、忽略数量以及比例，帮助判断规则是否过于敏感。

该功能应显示在 Rule Page 的内置规则表中。

---

## 6.2 Repository 层扩展

在 `AlertRepository` 中新增方法：

```python
rule_feedback()
```

按 `rule_id` 聚合以下字段：

```text
total
confirmed
ignored
unconfirmed
confirmed_ratio
ignored_ratio
```

字段含义：

| 字段                | 含义                |
| ----------------- | ----------------- |
| `total`           | 该规则产生的告警总数        |
| `confirmed`       | 被确认的告警数量          |
| `ignored`         | 被忽略的告警数量          |
| `unconfirmed`     | 尚未处理的告警数量         |
| `confirmed_ratio` | confirmed / total |
| `ignored_ratio`   | ignored / total   |

当 `total = 0` 时，比例应安全返回 0，避免除零错误。

---

## 6.3 Rule Page UI 要求

在：

```text
ui/rule_page.py
```

的内置规则表中，在 `Description` 后追加反馈相关列。

建议列包括：

```text
Feedback
Alerts
Confirmed
Ignored
```

或类似设计。

如果：

```text
ignored_ratio > 50%
```

则该规则对应的反馈单元格应：

1. 使用淡黄色背景；
2. 设置 tooltip，提示该规则可能产生较多被忽略告警。

示例 tooltip：

```text
More than 50% of alerts from this rule were ignored. Consider reviewing the rule threshold or conditions.
```

---

## 6.4 保存逻辑兼容要求

不得破坏现有规则配置保存逻辑。

尤其需要确认以下列仍然能够被正确读取和保存：

```text
Enabled
Threshold
Window
Description
```

如果表格列数变化，必须同步检查 `save_rules` 中的列索引，避免保存错位。

---

# 7. 测试与验证

## 7.1 测试目标

本轮开发需要增加或更新 pytest，重点覆盖非 GUI 逻辑。

如果 GUI 难以自动测试，至少保证 Repository、分析模块、PCAP 生成和检测流程有测试覆盖。

---

## 7.2 HostRiskScorer 测试

测试目标：

* 能根据严重等级、攻击链和 baseline 计算主机得分；
* 能正确排序 Top hosts；
* 高风险主机应排在低风险主机前；
* 空输入时不报错。

建议测试文件：

```text
tests/test_host_risk.py
```

---

## 7.3 AlertRepository 测试

测试目标：

1. `count_by_time_bucket()` 能正确按小时或天聚合；
2. `rule_feedback()` 能正确统计：

   * total
   * confirmed
   * ignored
   * unconfirmed
   * confirmed_ratio
   * ignored_ratio

建议测试文件：

```text
tests/test_alert_repository.py
```

---

## 7.4 Demo PCAP 测试

测试目标：

生成的：

```text
sample_data/demo_attack_chain.pcap
```

经过以下流程后：

```text
PcapLoader -> PacketParser -> DetectionEngine
```

能够产生预期 `rule_id` 告警。

至少验证以下规则中的多个被触发：

```text
HOST_SCAN
SQL_INJECTION
MALICIOUS_COMMAND
TLS_FINGERPRINT
LATERAL_MOVEMENT
ADMIN_SHARE_ACCESS
```

建议测试文件：

```text
tests/test_demo_pcap.py
```

---

## 7.5 RulePage 或规则保存测试

需要确认 Rule Page 新增反馈列后，不会破坏已有规则保存逻辑。

重点检查：

* Enabled 保存正常；
* Threshold 保存正常；
* Window 保存正常；
* Description 显示不影响保存；
* 新增 Feedback 相关列不会导致列索引错位。

---

## 7.6 运行测试

完成实现后运行：

```bash
pytest
```

如果部分 GUI 测试受环境限制无法执行，应至少保证非 GUI 测试通过，并在提交说明中明确说明 GUI 部分的人工验证方式。

---

# 8. UI 与文案要求

所有新增 UI 文案必须使用英文。

例如：

```text
High-risk hosts
Alert trend
Load demo data
Spike
No alert trend data available.
No high-risk hosts found.
```

不得在 UI 中混用中文文案。

---

# 9. TLS 功能表述限制

不得声称系统实现了 HTTPS 解密。

TLS 相关能力只能描述为：

```text
TLS metadata
TLS fingerprint
TLS fingerprint risk
```

不能描述为：

```text
HTTPS content inspection
HTTPS decryption
Decrypted TLS payload analysis
```

---

# 10. 开发约束

本轮开发应遵守以下约束：

1. 优先沿用现有代码风格；
2. 不引入重型新依赖；
3. 可以使用已存在于 `requirements.txt` 中的 Scapy；
4. 不直接插入假告警；
5. 不新增资产表；
6. 不破坏现有 Dashboard、Packet Page、Rule Page 的已有功能；
7. 不破坏已有规则配置保存逻辑；
8. 保持 UI 文案英文；
9. 所有新增非 GUI 逻辑应尽量有 pytest 覆盖。

---

# 11. 建议实现顺序

建议按以下顺序开发：

## Step 1：阅读现有架构

重点理解：

```text
AlertRepository
DetectionEngine
AttackChainAnalyzer
DashboardPage
PacketPage
RulePage
ChartWidget
```

---

## Step 2：实现 Repository 层扩展

优先完成：

```python
AlertRepository.count_by_time_bucket()
AlertRepository.rule_feedback()
```

因为告警趋势和规则反馈都依赖 Repository 层数据。

---

## Step 3：实现 Alert Trend Analysis

新增：

```text
detection/analysis/alert_trend.py
```

并在 Dashboard 中显示趋势数据。

---

## Step 4：实现 Host Risk Scoring

新增：

```text
detection/analysis/host_risk.py
```

复用：

```python
AttackChainAnalyzer.analyze()
```

并在 Dashboard 中新增 **High-risk hosts** 表格。

---

## Step 5：实现 Demo PCAP

新增：

```text
scripts/generate_demo_pcap.py
```

生成：

```text
sample_data/demo_attack_chain.pcap
```

确保演示流量能够触发现有规则，并能形成攻击链。

---

## Step 6：实现 Packet Page 一键演示

在：

```text
ui/packet_page.py
```

新增：

```text
Load demo data
```

按钮。

按钮应调用现有导入流程，不绕过检测引擎。

---

## Step 7：实现 Rule Feedback UI

在：

```text
ui/rule_page.py
```

中扩展规则表格。

新增反馈列后，必须检查规则保存逻辑的列索引是否仍然正确。

---

## Step 8：补充测试并运行 pytest

新增或更新测试后运行：

```bash
pytest
```

---

# 12. 验收标准

完成后应满足以下验收条件：

1. Dashboard 能显示 **High-risk hosts** 表格；
2. 每个高风险主机能显示综合评分和评分拆解；
3. Packet 页面存在 **Load demo data** 按钮；
4. 点击按钮后能导入 demo PCAP；
5. demo PCAP 产生的告警来自真实检测流程；
6. demo PCAP 能触发多种现有规则；
7. Dashboard 能显示 **Alert trend**；
8. Alert trend 能标记异常 spike；
9. Rule Page 能显示规则反馈数据；
10. ignored ratio 超过 50% 的规则有淡黄色提示；
11. 规则配置保存逻辑未被破坏；
12. 新增 UI 文案均为英文；
13. TLS 相关描述没有声称 HTTPS 解密；
14. pytest 至少覆盖主要非 GUI 逻辑；
15. `pytest` 运行通过，或对 GUI 受限部分给出明确说明。

---

# 13. 推荐提交信息

可以按功能拆分提交：

```text
feat: add host risk scoring analysis
feat: add demo pcap generation and one-click import
feat: add alert trend analysis
feat: add rule feedback metrics
test: add coverage for risk scoring and alert analytics
```

如果一次性提交，也可以使用：

```text
feat: add IDS dashboard analytics and demo workflow
```
