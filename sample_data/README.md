# Sample Data / 示例数据

[English README](../README.md) | [中文说明](../README.zh-CN.md) | [Demo Guide / 演示指南](../docs/demo_guide.md)

This directory stores deterministic demonstration captures and authorized course-lab samples. Do not add private production captures, credentials, decrypted third-party traffic, or data collected without permission.

本目录用于保存确定性演示抓包和经过授权的课程实验样例。请勿加入生产环境隐私抓包、凭据、未经授权的第三方解密流量或其他无权采集的数据。

Generate or regenerate the bundled attack-chain pcap from the project root:

在项目根目录生成或重新生成攻击链演示 pcap：

```powershell
python -m scripts.generate_demo_pcap
```

Output / 输出：

```text
sample_data/demo_attack_chain.pcap
```
