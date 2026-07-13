# 演示 pcap 使用说明

sample_data 目录下有一组合成的演示 pcap（demo_attack_chain.pcap），构造了一条从扫描到横向移动的完整攻击链，用来展示所有检测规则的实际效果。

## 包含了什么

pcap 里模拟了一个攻击者（10.0.0.99）对目标（10.0.1.50）的完整攻击过程，按时间线分为八个阶段：

- 侦察阶段：35 个不同 IP 的主机扫描 + 25 个端口的端口扫描，命中敏感端口（SSH、RDP、MySQL 等）
- 爆破阶段：对 SSH 和 RDP 的大量连接尝试
- 漏洞利用阶段：SQL 注入、XSS、路径遍历、SSRF、XXE、SSTI、webshell、Log4Shell
- 命令执行阶段：whoami、反弹 shell、PowerShell 编码执行、wget 下载、certutil
- C2 通信阶段：弱 TLS 握手、DNS 隧道和 DGA 域名、高危端口外联、C2 信标关键词
- 横向移动阶段：SMB 管理共享、RDP 跳板
- 攻击阶段：SYN flood 和 ICMP flood
- 异常行为：黑名单 IP 通信、带宽尖峰、大包 ML 异常、基线偏离

总计 400+ 个数据包，触发 21 条检测规则。

## 怎么用

打开 GUI，点左侧的流量监控，点工具栏上的 Load demo data。脚本会自动生成 pcap 并开始导入检测，几秒钟就能跑完。

然后切到告警中心，能看到按规则分类的告警列表，底部的 Attack chain view 会展示按源 IP 串联的攻击链。仪表盘上的趋势图和阶段分布也会同步更新。

## 自己重新生成

如果改了检测规则的参数或者想调整攻击场景，可以编辑 scripts/generate_demo_pcap.py 然后跑：

```
python -m scripts.generate_demo_pcap
```

文件会生成到 sample_data/demo_attack_chain.pcap。GUI 里的 Load demo data 按钮也会在文件不存在时自动调用这个脚本。
