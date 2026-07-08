# 测试报告

当前测试覆盖模型、数据库初始化、pcap 加载、Scapy 解析、检测引擎、5 个核心规则、自定义规则、告警保存和报告导出。

运行方式：

```powershell
.conda\Lightweight-IDS\python.exe -m pytest --basetemp .test_tmp -o cache_dir=.test_cache
```

最近一次验证结果：25 passed。
