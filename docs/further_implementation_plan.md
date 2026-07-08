# 实现计划

目前项目已经有了一个不错的基础框架：GUI 界面、pcap 导入、实时抓包、5 个检测规则、报告导出这些都已经跑通了。但跟课程要求对比，还缺不少东西。下面分阶段补上。

## 阶段一：特征匹配检测

这部分是课程明确要求的，也是目前最缺的。要做 SQL 注入检测、XSS 检测、Web 攻击检测、恶意命令检测，还有把三个空壳规则（暴力破解、HTTP 可疑请求、DNS 异常）真正实现出来。

### SQL 注入检测

新建一个规则文件，在 HTTP 请求的 payload 里匹配 SQL 注入的典型特征，比如 UNION SELECT、OR 1=1、DROP TABLE、xp_cmdshell 这类关键词。命中就告警，等级设为 CRITICAL。

### XSS 检测

新建规则文件，匹配 XSS 特征，比如 script 标签、javascript 伪协议、onerror 事件、alert 调用、document.cookie 等。命中即告警，等级 HIGH。

### Web 攻击检测

新建规则文件，把现有的 http_suspicious.py 空壳替换掉。检测目录遍历（../ 之类的）、命令注入（; id、| ls、反引号包裹命令）、SSRF（访问 169.254.169.254 等内网地址）、文件包含、反序列化 payload。等级 HIGH。

### 恶意命令检测

新建规则文件，检测流量中出现的恶意系统命令，比如 whoami、net user、反弹 shell 的各种写法（/dev/tcp、bash -i >&）、powershell -enc 编码执行、wget/curl 下载等。等级 CRITICAL。

### 暴力破解检测

brute_force.py 已经有了，但 process 方法是空的。用项目里现成的 WindowCounter 滑动窗口来实现：同一源 IP 短时间内对 SSH、RDP、FTP、MySQL 等常见服务端口发起大量连接尝试，超过阈值就报。默认 10 次/10 秒，等级 HIGH。

### DNS 异常检测

dns_anomaly.py 也是空的，补上。检测三种情况：DNS 隧道（超长域名查询，超过 52 字符）、DGA 域名（高熵值随机字符串域名）、高频 DNS 查询。等级 MEDIUM。

## 阶段二：异常行为检测

这部分也是课程要求的，需要建立基线然后识别偏离。

### 异常外联检测

新建规则，检测内网主机往外连的可疑行为：访问陌生外部 IP、使用非标准端口出站、固定间隔的心跳通信（C2 常见特征）。等级 HIGH。

### 横向扩散检测

新建规则，检测内网横向移动：同一台机器短时间内连了多个内网目标的 SMB、RDP、SSH 端口，或者访问了管理员共享（\\ADMIN$、\\C$）。等级 CRITICAL。

### 主机扫描检测

现有的 port_scan 是检测单源对单目标的多端口扫描，缺一个主机扫描的检测：同一源 IP 短时间内访问大量不同目标 IP。等级 HIGH。

## 阶段三：扩展功能

### TLS 指纹分析

不需要解密 TLS，分析握手阶段的特征就行。提取 TLS 版本、加密套件、扩展列表，跟已知恶意软件的 JA3 指纹库对比。同时检测弱加密套件（NULL、EXPORT、RC4、DES 等）和自签名证书。等级 MEDIUM。

### ML 异常检测

simple_anomaly.py 现在是空壳。用 sklearn 的 IsolationForest 做无监督异常检测。先从 PacketRecord 里提取特征（包大小、端口、协议、时间间隔等），按 IP 聚合，在正常流量上训练，然后对偏离流量打分。需要额外写一个特征工程文件。

### 攻击链关联分析

把零散的告警按时间线和源 IP 串起来，对应到 MITRE ATT&CK 的各个阶段：扫描 → 漏洞利用 → 执行恶意命令 → C2 外联 → 横向扩散。在告警中心增加一个攻击链视图来展示。

### 误报降噪

项目里已经有 alert_cooldown_seconds 机制，但还不够。需要加上白名单 IP 过滤（内部扫描器、监控系统）、资产重要性评估（低价值资产告警降级）、同类告警自动合并。

## 阶段四：GUI 调整

- 仪表盘增加攻击链时间线卡片和异常评分趋势图
- 告警中心增加攻击链视图，展示告警之间的关联
- 规则管理自动注册所有新规则

## 实现方式

所有新规则都沿用现有的模式：继承 RuleBase，实现 process 方法接收 PacketRecord 返回告警列表，用 WindowCounter 做滑动窗口统计，用 create_alert 工厂方法生成告警。新规则需要在 rules.yaml、migrations.py 和 DetectionEngine 里注册。