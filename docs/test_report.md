# 测试报告

当前阶段包含模型、数据库初始化、pcap 加载、Scapy 解析、检测引擎、5 个核心规则、告警保存和报告导出的基础测试。

运行方式：

```powershell
pytest
```

本机如果默认临时目录没有权限，可以运行：

```powershell
.conda\Lightweight-IDS\python.exe -m pytest --basetemp .test_tmp -o cache_dir=.test_cache
```

最近一次验证结果：21 passed。
