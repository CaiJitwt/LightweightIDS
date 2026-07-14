import {
  Activity,
  ArrowRight,
  BellRing,
  BriefcaseBusiness,
  Gauge,
  HeartPulse,
  Languages,
  Network,
  Package,
  Palette,
  ScrollText,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Timeline,
  Waypoints,
} from "lucide-react";

export type HelpTarget = "dashboard" | "traffic" | "hosts" | "alerts" | "investigations" | "assets" | "rules" | "reports" | "timeline" | "topology" | "security-events" | "health" | "endpoint" | "settings" | "personalization";
export type HelpLanguage = "en" | "zh";

interface LocalizedTopic {
  title: string;
  summary: string;
  tips: string[];
}

interface HelpTopic {
  target: HelpTarget;
  icon: typeof Gauge;
  en: LocalizedTopic;
  zh: LocalizedTopic;
}

const topics: HelpTopic[] = [
  {
    target: "dashboard", icon: Gauge,
    en: { title: "Dashboard", summary: "Review overall traffic, alerts, trends and the hosts that currently need attention.", tips: ["Use the auto-refresh control for a continuously updated overview.", "Open an alert or high-risk host directly from its table."] },
    zh: { title: "仪表盘", summary: "查看整体流量、告警趋势以及当前最需要关注的高风险主机。", tips: ["开启自动刷新后，概览数据会定期更新。", "可以从表格直接打开告警或高风险主机。"] },
  },
  {
    target: "traffic", icon: Activity,
    en: { title: "Traffic Monitor", summary: "Start live capture, import PCAP files and inspect packet metadata as it arrives.", tips: ["Select an interface and optional capture filter before starting.", "Use the packet table filters to narrow the visible results without restarting capture."] },
    zh: { title: "流量监控", summary: "启动实时抓包、导入 PCAP 文件并查看持续到达的数据包元数据。", tips: ["启动前选择网络接口，并按需设置抓包过滤器。", "使用数据包表格过滤器缩小显示范围，无需重启抓包。"] },
  },
  {
    target: "hosts", icon: Network,
    en: { title: "Host Explorer", summary: "Inspect observed hosts, risk scores, peers, ports, protocols and related alerts.", tips: ["Search by IP address or asset name.", "Use the detail tabs to compare connections, alerts and the host timeline."] },
    zh: { title: "主机分析", summary: "查看已发现主机的风险评分、通信对象、端口、协议和相关告警。", tips: ["可以按 IP 地址或资产名称搜索。", "通过详情标签比较连接、告警和主机时间线。"] },
  },
  {
    target: "alerts", icon: BellRing,
    en: { title: "Alert Center", summary: "Review detection evidence, related packets and analyst confirmation status.", tips: ["Select an alert to inspect every associated packet and its full metadata.", "Confirm, ignore or add relevant evidence to an investigation."] },
    zh: { title: "告警中心", summary: "核查检测证据、关联数据包和分析人员确认状态。", tips: ["选择告警后可以查看全部关联数据包及其完整元数据。", "可以确认、忽略告警，或将证据加入调查。"] },
  },
  {
    target: "investigations", icon: BriefcaseBusiness,
    en: { title: "Investigations", summary: "Organize analyst notes and preserve alert evidence as durable snapshots.", tips: ["Track cases with Open, Monitoring and Closed states.", "Export an investigation to HTML for review or submission."] },
    zh: { title: "调查管理", summary: "整理分析记录，并将告警证据保存为不会随统计重置消失的快照。", tips: ["使用 Open、Monitoring 和 Closed 状态跟踪案例。", "可以将单个调查导出为 HTML 文件。"] },
  },
  {
    target: "assets", icon: Package,
    en: { title: "Assets", summary: "Register important IP addresses, roles and business importance for risk prioritization.", tips: ["Use a unique valid IP address for every asset.", "Higher importance increases the priority of alerts involving that asset."] },
    zh: { title: "资产管理", summary: "登记重要 IP、设备角色和业务重要性，用于风险排序。", tips: ["每个资产应使用唯一且有效的 IP 地址。", "重要性越高，涉及该资产的告警优先级越高。"] },
  },
  {
    target: "rules", icon: SlidersHorizontal,
    en: { title: "Rule Management", summary: "Enable detectors and tune their rule-specific thresholds and observation windows.", tips: ["Read the Detection and tuning column before changing a value.", "Saved changes apply when a new live capture or PCAP analysis session starts."] },
    zh: { title: "规则管理", summary: "启用检测器，并调整各规则对应的阈值和观察时间窗口。", tips: ["修改前请阅读 Detection and tuning 列中的参数说明。", "保存的修改会在新的实时抓包或 PCAP 分析会话中生效。"] },
  },
  {
    target: "reports", icon: Timeline,
    en: { title: "Reports", summary: "Export persisted alerts and analyst records in formats suitable for review.", tips: ["Apply the available filters before exporting a focused report.", "Review sensitive evidence before sharing generated files."] },
    zh: { title: "报告", summary: "将已保存的告警和分析记录导出为便于查看的报告。", tips: ["导出前使用过滤器生成更有针对性的报告。", "分享文件前应检查其中是否包含敏感证据。"] },
  },
  {
    target: "timeline", icon: Timeline,
    en: { title: "Event Timeline", summary: "Correlate packets, alerts and analyst activity in chronological order.", tips: ["Use severity and event-type filters to reduce noise.", "Follow adjacent events to reconstruct the order of suspicious activity."] },
    zh: { title: "事件时间线", summary: "按照时间顺序关联数据包、告警和分析活动。", tips: ["使用严重等级和事件类型过滤器减少干扰。", "结合相邻事件还原可疑活动发生顺序。"] },
  },
  {
    target: "topology", icon: Waypoints,
    en: { title: "Network Topology", summary: "Explore observed communication paths and the relationship between internal and external hosts.", tips: ["Select a node to inspect its role and activity.", "Use topology as supporting context rather than proof of compromise."] },
    zh: { title: "网络拓扑", summary: "查看已发现的通信路径以及内外网主机之间的关系。", tips: ["选择节点可以查看设备角色和活动信息。", "拓扑用于提供分析上下文，不能单独作为入侵证据。"] },
  },
  {
    target: "health", icon: HeartPulse,
    en: { title: "System Health", summary: "Check local API connectivity, detector status and sensor runtime indicators.", tips: ["An offline engine means persisted and live functions may be unavailable.", "Use detector status and queue indicators when diagnosing delayed updates."] },
    zh: { title: "系统健康", summary: "检查本地 API 连接、检测器状态和传感器运行指标。", tips: ["引擎离线时，持久化数据和实时功能可能不可用。", "更新延迟时可以检查检测器状态和队列指标。"] },
  },
  {
    target: "security-events", icon: ScrollText,
    en: { title: "Security Events", summary: "Monitor selected Windows Event Log channels for authentication, persistence and security-control activity.", tips: ["Start monitoring explicitly or enable it in Settings.", "Windows audit policy and PowerShell Script Block Logging determine which events are available.", "Open a generated alert to correlate the normalized host event with other evidence."] },
    zh: { title: "安全事件", summary: "监控选定的 Windows 事件日志通道，分析身份验证、持久化和安全控制变更。", tips: ["可以在页面中手动启动，也可以在设置中启用持续监控。", "Windows 审计策略和 PowerShell 脚本块日志设置会影响可采集的事件。", "打开生成的告警，可以将标准化主机事件与其他证据关联核实。"] },
  },
  {
    target: "endpoint", icon: ShieldCheck,
    en: { title: "Endpoint Security", summary: "Review read-only Windows posture, processes, ports and file-integrity observations.", tips: ["Treat unavailable checks as missing visibility, not a security pass.", "Correlate endpoint observations with network alerts before escalation."] },
    zh: { title: "终端安全", summary: "查看只读的 Windows 安全状态、进程、端口和文件完整性信息。", tips: ["检查不可用代表缺少可见性，并不表示安全。", "升级处置前，应将终端信息与网络告警关联核实。"] },
  },
  {
    target: "settings", icon: Settings,
    en: { title: "Settings", summary: "Configure theme, font scale, capture behavior, alert policy and optional LLM guidance.", tips: ["System theme follows the operating-system color preference.", "The LLM API key is kept in session storage and should still be handled carefully."] },
    zh: { title: "设置", summary: "配置主题、字号、抓包行为、告警策略和可选的 LLM 防御建议。", tips: ["系统主题会跟随操作系统的明暗模式。", "LLM API Key 保存在会话存储中，但仍应谨慎管理。"] },
  },
  {
    target: "personalization", icon: Palette,
    en: { title: "Personalization", summary: "Choose an accent color, workspace wallpaper and optional transparent companion image.", tips: ["Adjust image size, position and opacity to keep controls unobstructed.", "Large local images may exceed browser storage limits."] },
    zh: { title: "个性化", summary: "选择强调色、工作区壁纸和可选的透明虚拟宠物图片。", tips: ["调整图片大小、位置和透明度，避免遮挡主要控件。", "过大的本地图片可能超出浏览器存储限制。"] },
  },
];

const copy = {
  en: {
    title: "Help Center", subtitle: "Learn the analyst workflow and open any workspace directly.", language: "Help language", quick: "Quick navigation", workflow: "Recommended workflow",
    steps: ["Start the local API and confirm that System Health shows the engine as connected.", "Open Traffic Monitor, select an interface or PCAP file, then start analysis.", "Review alerts and associated packets before confirming or ignoring them.", "Create investigations, tune noisy rules and export reports when the evidence is ready."],
    modules: "Workspace guide", open: "Open page", notes: "Important notes",
    noteItems: ["Live capture normally requires Npcap and sufficient Windows permissions.", "TLS detection uses metadata and fingerprint risk only; this application does not decrypt HTTPS traffic.", "Rule changes apply to future detection sessions, while existing alerts remain unchanged.", "Reset statistics removes packets, alerts and baselines, but preserves assets, investigations and evidence snapshots."],
  },
  zh: {
    title: "帮助中心", subtitle: "了解分析工作流，并快速打开任意功能页面。", language: "帮助页面语言", quick: "快速导航", workflow: "推荐使用流程",
    steps: ["启动本地 API，并确认系统健康页面显示引擎已连接。", "打开流量监控，选择网络接口或 PCAP 文件，然后开始分析。", "确认或忽略告警前，应检查告警证据及其关联数据包。", "证据整理完成后，可以创建调查、调整误报较多的规则并导出报告。"],
    modules: "功能页面说明", open: "打开页面", notes: "重要说明",
    noteItems: ["实时抓包通常需要安装 Npcap，并具有足够的 Windows 权限。", "TLS 检测仅分析元数据和指纹风险，本程序不会解密 HTTPS 流量。", "规则修改对后续检测会话生效，不会改变已经生成的告警。", "重置统计会清除数据包、告警和基线，但会保留资产、调查和证据快照。"],
  },
};

export function HelpPage({ onNavigate, language, onLanguageChange }: { onNavigate: (target: HelpTarget) => void; language: HelpLanguage; onLanguageChange: (language: HelpLanguage) => void }) {
  const text = copy[language];

  return (
    <div className="page-stack help-page">
      <section className="help-intro">
        <div><span className="eyebrow">Lightweight IDS</span><h2>{text.title}</h2><p>{text.subtitle}</p></div>
        <div className="help-language"><span><Languages size={15} />{text.language}</span><div className="theme-segment" role="group" aria-label={text.language}><button type="button" className={language === "en" ? "selected" : ""} onClick={() => onLanguageChange("en")}>English</button><button type="button" className={language === "zh" ? "selected" : ""} onClick={() => onLanguageChange("zh")}>中文</button></div></div>
      </section>

      <section className="section-panel help-quick-nav">
        <header className="section-heading"><div><h2>{text.quick}</h2><p>{language === "en" ? "Jump directly to a workspace" : "直接跳转到对应功能页面"}</p></div></header>
        <div>{topics.map((topic) => { const localized = topic[language]; const Icon = topic.icon; return <button type="button" key={topic.target} onClick={() => onNavigate(topic.target)}><Icon size={14} /><span>{localized.title}</span></button>; })}</div>
      </section>

      <section className="section-panel">
        <header className="section-heading"><div><h2>{text.workflow}</h2><p>{language === "en" ? "A practical path from capture to evidence" : "从抓包到证据整理的实用流程"}</p></div></header>
        <ol className="help-workflow">{text.steps.map((step, index) => <li key={step}><span>{index + 1}</span><p>{step}</p></li>)}</ol>
      </section>

      <section className="help-module-section">
        <div className="help-section-title"><h2>{text.modules}</h2><span>{topics.length}</span></div>
        <div className="help-module-grid">
          {topics.map((topic) => {
            const localized = topic[language];
            const Icon = topic.icon;
            return <article className="help-module" key={topic.target}><header><span><Icon size={18} /></span><h3>{localized.title}</h3></header><p>{localized.summary}</p><ul>{localized.tips.map((tip) => <li key={tip}>{tip}</li>)}</ul><button type="button" className="text-button" onClick={() => onNavigate(topic.target)}>{text.open}<ArrowRight size={14} /></button></article>;
          })}
        </div>
      </section>

      <section className="section-panel">
        <header className="section-heading"><div><h2>{text.notes}</h2><p>{language === "en" ? "Runtime and analysis boundaries" : "运行要求和分析边界"}</p></div></header>
        <ul className="help-notes">{text.noteItems.map((note) => <li key={note}>{note}</li>)}</ul>
      </section>
    </div>
  );
}
