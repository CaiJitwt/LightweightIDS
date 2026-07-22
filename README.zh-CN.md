# Lightweight IDS

[English](README.md) | [简体中文](README.zh-CN.md)

Lightweight IDS 是一个面向本地防御分析的入侵检测与分析工作流项目，使用 Python 3.11、Scapy、SQLite、PySide6 和 React 现代前端构建。项目支持离线数据包分析、实时抓包、规则检测、端点遥测、告警调查、资产风险评分和防御报告导出。

本项目适用于课程作业、授权实验环境，以及对本人有权检查的系统和流量进行防御分析。

## 界面选择

| 界面 | 启动命令 | 适用场景 |
| --- | --- | --- |
| 现代分析工作台 | `python modern_main.py` | 浏览器工作流、丰富图表、实时抓包、网络拓扑、端点安全和 LLM 建议 |
| 经典 PySide6 桌面端 | `python main.py` | 原生工作流、自定义规则、强制黑名单和持久调查证据 |

两套界面默认共用同一个 SQLite 数据库：`data/lightweight_ids.db`。

## 主要功能

- 导入 `.pcap`、`.pcapng` 和 `.cap` 文件，或从本地网络接口实时抓包。
- 通过正常 Detection Engine 执行可配置的内置规则和自定义规则。
- 在确认或忽略告警前查看告警证据及全部关联数据包。
- 结合资产重要性、行为基线和攻击链上下文计算主机综合风险。
- 管理资产，并通过证据快照持久保留人工调查记录。
- 在 Host Explorer 和 Network Topology 中查看真实抓包形成的连接关系。
- 在 Rule Management 中调整规则阈值和时间窗口，并保存到 SQLite。
- 管理 IP 和端口拦截项；在系统支持且权限允许时尝试写入 Windows 防火墙。
- 查看 Windows 安全事件、进程清单、文件完整性和本机运行状态。
- 对 CPU 或受支持 NVIDIA GPU 的长期高负载生成排查信号，用于辅助发现挖矿或恶意程序。
- 导出持久化告警和调查证据。
- 跟随系统亮色/暗色主题、调整字号，并保存壁纸和悬浮宠物设置。
- 可选接入 OpenAI 兼容 LLM，由分析人员主动请求中文或英文防御建议。

## 环境要求

- Python 3.11 或更高版本
- `requirements.txt` 中的 Python 依赖
- Windows 实时抓包需要安装 Npcap，并具备相应权限
- 现代前端需要 Node.js 22.12 或更高版本
- GPU 利用率监控需要 NVIDIA 驱动提供 `nvidia-smi`；CPU 监控不依赖该工具

程序不会从抓包文件中解密 HTTPS 正文。TLS 仅进行元数据和指纹风险分析。需要进行授权的应用层实验时，请阅读 [HTTPS 实验流程](docs/https_lab_workflow.md)。

## 安装

创建或激活 Python 3.11+ 环境，然后安装 Python 依赖：

```powershell
python -m pip install -r requirements.txt
```

现代前端启动器会在第一次运行时自动安装缺失的前端包，也可以手动安装：

```powershell
cd modern_frontend
npm install
cd ..
```

## 启动现代分析工作台

在项目根目录运行：

```powershell
python modern_main.py
```

启动器会初始化数据库，为本地 API 和前端自动选择两个可用的回环端口，输出两个访问地址，并自动打开浏览器。

常用选项：

```powershell
python modern_main.py --no-browser
python modern_main.py --skip-install
python modern_main.py --database .\data\custom_ids.db
python modern_main.py --api-port 8787 --frontend-port 4173
```

在启动器终端按 `Ctrl+C`，可以停止本次启动器创建的服务。

现代 Assets 和 Investigations 页面已经通过本地 API v8 实现新建、读取、编辑和删除，并持久化到 SQLite。经典桌面端还额外支持添加/移除告警证据快照和导出调查 HTML。

## 启动经典桌面端

```powershell
python main.py
```

经典界面包含 Dashboard、Traffic Monitor、Host Explorer、Alert Center、Investigations、Assets、Rule Management、Reports、Settings 和 Personalization 页面。

## 快速演示

生成时间确定的演示抓包：

```powershell
python -m scripts.generate_demo_pcap
```

然后导入 `sample_data/demo_attack_chain.pcap`。经典 Traffic Monitor 在文件不存在时也可以通过 `Load demo data` 自动生成并导入。详细说明见 [演示指南](docs/demo_guide.md)。

## 重置行为

`Reset statistics` 会清除运行期数据包、告警、行为基线和 Windows 安全事件，并重置相应计数。Reports 和 Event Timeline 中的运行数据也会同时归零。

资产、调查记录和调查证据快照会被保留。只有在确实需要完全恢复全新应用状态时，才应删除或替换 SQLite 数据库。

## 检测与响应边界

- 检测告警是供人工核实的证据，不代表主机已经被确认攻陷。
- CPU/GPU 长期高负载也可能来自编译、渲染、游戏或正常计算任务。
- 离线数据包代表历史流量，无法被事后拦截。
- 只有拦截项状态为 `Active` 时，未来匹配流量才会被系统拒绝。
- 自动拦截目前使用 Windows 防火墙，通常需要管理员权限。
- 程序不会解密 HTTPS 正文、安装中间人证书、利用目标漏洞或扫描公网系统。

## 测试

后端和 PySide6 测试：

```powershell
python -m pytest
```

现代前端测试和生产构建：

```powershell
cd modern_frontend
npm test
npm run build
npm run test:e2e
```

运行 Playwright 前，请将 `PLAYWRIGHT_BASE_URL` 设置为启动器输出的前端地址。

## 文档

- [文档索引](docs/README.zh-CN.md)
- [用户手册](docs/user_manual.zh-CN.md)
- [系统设计](docs/system_design.md)
- [HTTPS 实验流程](docs/https_lab_workflow.md)
- [防护工作流](docs/protection_workflow.md)
- [演示指南](docs/demo_guide.md)

## 仓库结构

| 路径 | 作用 |
| --- | --- |
| `capture/`、`parser/` | 实时抓包、过滤、pcap 加载和数据包标准化 |
| `detection/` | 检测引擎、规则、分析、行为基线和降噪 |
| `storage/`、`models/` | SQLite 迁移、仓储和共享数据记录 |
| `ui/` | 经典 PySide6 应用 |
| `modern_frontend/`、`modern_ui/` | React 分析工作台和本地 Python API |
| `endpoint_security/`、`protection/` | 主机遥测、安全事件、完整性检查和拦截执行 |
| `report/` | 报告与调查导出 |
| `scripts/`、`sample_data/` | 确定性演示数据生成和样例材料 |
| `tests/` | Python 和集成测试 |

## 许可证

参见 [LICENSE](LICENSE)。
