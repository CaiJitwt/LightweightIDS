import { lazy, Suspense, useEffect, useState } from "react";
import {
  Activity,
  BellRing,
  BriefcaseBusiness,
  ChevronLeft,
  ChevronRight,
  Gauge,
  HeartPulse,
  CircleHelp,
  Laptop,
  Moon,
  Network,
  Package,
  Palette,
  RefreshCw,
  Search,
  ScrollText,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Timeline,
  Waypoints,
} from "lucide-react";
import type { FontScale, LlmSettings, ThemePreference } from "./types";
import type { PersonalizationState } from "./pages/PersonalizationPage";
import type { HelpLanguage } from "./pages/HelpPage";
import { idsApi } from "./api/idsApi";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const TrafficPage = lazy(() => import("./pages/TrafficPage").then((module) => ({ default: module.TrafficPage })));
const HostsPage = lazy(() => import("./pages/HostsPage").then((module) => ({ default: module.HostsPage })));
const AlertsPage = lazy(() => import("./pages/AlertsPage").then((module) => ({ default: module.AlertsPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((module) => ({ default: module.SettingsPage })));
const EndpointSecurityPage = lazy(() => import("./pages/EndpointSecurityPage").then((module) => ({ default: module.EndpointSecurityPage })));
const InvestigationsPage = lazy(() => import("./pages/InvestigationsPage").then((module) => ({ default: module.InvestigationsPage })));
const AssetsPage = lazy(() => import("./pages/AssetsPage").then((module) => ({ default: module.AssetsPage })));
const RulesPage = lazy(() => import("./pages/RulesPage").then((module) => ({ default: module.RulesPage })));
const ReportsPage = lazy(() => import("./pages/ReportsPage").then((module) => ({ default: module.ReportsPage })));
const PersonalizationPage = lazy(() => import("./pages/PersonalizationPage").then((module) => ({ default: module.PersonalizationPage })));
const EventTimelinePage = lazy(() => import("./pages/EventTimelinePage").then((module) => ({ default: module.EventTimelinePage })));
const NetworkTopologyPage = lazy(() => import("./pages/NetworkTopologyPage").then((module) => ({ default: module.NetworkTopologyPage })));
const SystemHealthPage = lazy(() => import("./pages/SystemHealthPage").then((module) => ({ default: module.SystemHealthPage })));
const HelpPage = lazy(() => import("./pages/HelpPage").then((module) => ({ default: module.HelpPage })));
const SecurityEventsPage = lazy(() => import("./pages/SecurityEventsPage").then((module) => ({ default: module.SecurityEventsPage })));

type PageKey = "dashboard" | "traffic" | "hosts" | "alerts" | "investigations" | "assets" | "rules" | "reports" | "timeline" | "topology" | "security-events" | "health" | "endpoint" | "settings" | "personalization" | "help";

const navItems = [
  { key: "dashboard" as const, label: "Dashboard", icon: Gauge },
  { key: "traffic" as const, label: "Traffic Monitor", icon: Activity },
  { key: "hosts" as const, label: "Host Explorer", icon: Network },
  { key: "alerts" as const, label: "Alert Center", icon: BellRing },
  { key: "investigations" as const, label: "Investigations", icon: BriefcaseBusiness },
  { key: "assets" as const, label: "Assets", icon: Package },
  { key: "rules" as const, label: "Rule Management", icon: SlidersHorizontal },
  { key: "reports" as const, label: "Reports", icon: Timeline },
  { key: "timeline" as const, label: "Event Timeline", icon: Timeline },
  { key: "topology" as const, label: "Network Topology", icon: Waypoints },
  { key: "security-events" as const, label: "Security Events", icon: ScrollText },
  { key: "health" as const, label: "System Health", icon: HeartPulse },
  { key: "endpoint" as const, label: "Endpoint Security", icon: ShieldCheck },
  { key: "settings" as const, label: "Settings", icon: Settings },
  { key: "personalization" as const, label: "Personalization", icon: Palette },
  { key: "help" as const, label: "Help Center", icon: CircleHelp },
];

const pageMeta: Record<PageKey, { title: string; subtitle: string }> = {
  dashboard: { title: "Security overview", subtitle: "Current network posture and analyst priorities" },
  traffic: { title: "Traffic monitor", subtitle: "Live packet metadata from the active capture interface" },
  hosts: { title: "Host explorer", subtitle: "Observed assets, connections and composite risk" },
  alerts: { title: "Alert center", subtitle: "Review evidence, related packets and analyst status" },
  investigations: { title: "Investigations", subtitle: "Preserve analyst evidence and investigation notes" },
  assets: { title: "Assets", subtitle: "Define high-value systems for risk prioritization" },
  rules: { title: "Rule management", subtitle: "Tune enabled detection rules and time windows" },
  reports: { title: "Reports", subtitle: "Export analyst-friendly persisted alert records" },
  timeline: { title: "Event timeline", subtitle: "Correlate observed events across the analyst workflow" },
  topology: { title: "Network topology", subtitle: "Explore observed hosts and communication paths" },
  "security-events": { title: "Security events", subtitle: "Monitor Windows authentication, persistence and security-control activity" },
  health: { title: "System health", subtitle: "Review sensor and local service readiness" },
  endpoint: { title: "Endpoint security", subtitle: "Read-only host posture, process inventory and file integrity" },
  settings: { title: "Settings", subtitle: "Appearance and local analyst integrations" },
  personalization: { title: "Personalization", subtitle: "Workspace wallpaper and overlay companion" },
  help: { title: "Help center", subtitle: "Product guidance, analyst workflow and quick navigation" },
};

const defaultPersonalization: PersonalizationState = { accent: "#2677bd", background: "", petImage: "", petPosition: "bottom-right", petSize: 96, petOpacity: 85 };

export default function App() {
  const [page, setPage] = useState<PageKey>("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => readThemePreference());
  const [fontScale, setFontScale] = useState<FontScale>(() => readFontScale());
  const systemDark = useSystemDarkMode();
  const theme = themePreference === "system" ? (systemDark ? "dark" : "light") : themePreference;
  const [llmSettings, setLlmSettings] = useState<LlmSettings>(defaultLlmSettings);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [selectedHostIp, setSelectedHostIp] = useState<string | undefined>();
  const [personalization, setPersonalization] = useState<PersonalizationState>(readPersonalization);
  const [helpLanguage, setHelpLanguage] = useState<HelpLanguage>(readHelpLanguage);
  const [openAlertCount, setOpenAlertCount] = useState(0);
  const [alertBadgeRefresh, setAlertBadgeRefresh] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<number | undefined>();

  useEffect(() => {
    localStorage.setItem("ids-prototype-theme", themePreference);
  }, [themePreference]);

  useEffect(() => {
    localStorage.setItem("ids-prototype-font-scale", fontScale);
  }, [fontScale]);

  useEffect(() => {
    let active = true;
    idsApi.settings()
      .then((settings) => { if (active) setLlmSettings(llmSettingsFromRuntime(settings)); })
      .catch(() => undefined);
    return () => { active = false; };
  }, []);

  useEffect(() => {
    try { localStorage.setItem("ids-prototype-personalization", JSON.stringify(personalization)); } catch { /* Browser storage can reject large image data. */ }
  }, [personalization]);

  useEffect(() => localStorage.setItem("ids-help-language", helpLanguage), [helpLanguage]);

  useEffect(() => {
    let active = true;
    const syncOpenAlerts = () => idsApi.dashboard()
      .then((snapshot) => { if (active) setOpenAlertCount(Math.max(0, snapshot.statistics.openAlerts)); })
      .catch(() => { if (active) setOpenAlertCount(0); });
    void syncOpenAlerts();
    const timer = autoRefresh ? window.setInterval(syncOpenAlerts, 5000) : undefined;
    return () => { active = false; if (timer !== undefined) window.clearInterval(timer); };
  }, [alertBadgeRefresh, autoRefresh]);

  useEffect(() => {
    if (!autoRefresh || page !== "dashboard") return undefined;
    const timer = window.setInterval(() => setRefreshVersion((value) => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, page]);

  const meta = page === "help" && helpLanguage === "zh"
    ? { title: "帮助中心", subtitle: "产品说明、分析工作流和快速页面导航" }
    : pageMeta[page];

  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`} data-theme={theme} data-font-scale={fontScale} style={{ "--accent": personalization.accent } as React.CSSProperties}>
      <aside className="sidebar">
        <div className="brand-block"><span className="brand-mark"><Shield size={20} /></span><span className="brand-copy"><strong>Lightweight IDS</strong><small>Analyst console</small></span></div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const badge = item.key === "alerts" && openAlertCount > 0 ? (openAlertCount > 99 ? "99+" : openAlertCount) : null;
            return <button type="button" key={item.key} className={page === item.key ? "active" : ""} onClick={() => setPage(item.key)} title={collapsed ? item.label : undefined}><Icon size={18} /><span>{item.label}</span>{badge !== null && <b title={`${openAlertCount} unconfirmed alerts`}>{badge}</b>}</button>;
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="sensor-summary"><span className="live-dot" /><span><strong>Sensor online</strong><small>Ethernet 3 - 1.2k pkt/min</small></span></div>
          <button type="button" className="collapse-button" onClick={() => setCollapsed((value) => !value)} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>{collapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}<span>Collapse</span></button>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="page-heading"><h1>{meta.title}</h1><p>{meta.subtitle}</p></div>
          <div className="topbar-actions">
            <button className="global-search" type="button"><Search size={16} /><span>Search</span><kbd>Ctrl K</kbd></button>
            {page === "dashboard" && <label className="refresh-toggle"><input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} /><span>Auto-refresh</span></label>}
            <button className="icon-button" type="button" title="Refresh current view" onClick={() => { setRefreshVersion((value) => value + 1); setAlertBadgeRefresh((value) => value + 1); }}><RefreshCw size={17} /></button>
            <button className="icon-button" type="button" title={`Use ${theme === "light" ? "dark" : "light"} theme`} onClick={() => setThemePreference(theme === "light" ? "dark" : "light")}>{theme === "light" ? <Moon size={17} /> : <Sun size={17} />}</button>
            <button className="user-button" type="button" title="Analyst profile"><Laptop size={16} /><span>Analyst</span></button>
          </div>
        </header>
        <div className="page-content">
          <Suspense fallback={<div className="page-loading">Loading view...</div>}>
            {page === "dashboard" && <DashboardPage refreshVersion={refreshVersion} onStatisticsReset={() => { setRefreshVersion((value) => value + 1); setAlertBadgeRefresh((value) => value + 1); }} onOpenAlertCountChange={setOpenAlertCount} onOpenAlerts={() => setPage("alerts")} onOpenHost={(ip) => { setSelectedHostIp(ip); setPage("hosts"); }} />}
            {page === "traffic" && <TrafficPage />}
            {page === "hosts" && <HostsPage initialHostIp={selectedHostIp} refreshVersion={refreshVersion} />}
            {page === "alerts" && <AlertsPage llmSettings={llmSettings} refreshVersion={refreshVersion} initialAlertId={selectedAlertId} onAlertsChanged={() => setAlertBadgeRefresh((value) => value + 1)} />}
            {page === "investigations" && <InvestigationsPage />}
            {page === "assets" && <AssetsPage />}
            {page === "rules" && <RulesPage />}
            {page === "reports" && <ReportsPage />}
            {page === "timeline" && <EventTimelinePage />}
            {page === "topology" && <NetworkTopologyPage refreshVersion={refreshVersion} />}
            {page === "security-events" && <SecurityEventsPage onOpenAlert={(alertId) => { setSelectedAlertId(alertId); setPage("alerts"); }} />}
            {page === "health" && <SystemHealthPage refreshVersion={refreshVersion} />}
            {page === "endpoint" && <EndpointSecurityPage refreshVersion={refreshVersion} />}
            {page === "settings" && <SettingsPage themePreference={themePreference} onThemePreferenceChange={setThemePreference} fontScale={fontScale} onFontScaleChange={setFontScale} llmSettings={llmSettings} onLlmSettingsChange={setLlmSettings} />}
            {page === "personalization" && <PersonalizationPage state={personalization} onChange={setPersonalization} />}
            {page === "help" && <HelpPage onNavigate={setPage} language={helpLanguage} onLanguageChange={setHelpLanguage} />}
          </Suspense>
        </div>
      </main>
      {personalization.petImage && <img className={`overlay-pet ${personalization.petPosition}`} src={personalization.petImage} alt="" style={{ width: personalization.petSize, opacity: personalization.petOpacity / 100 }} />}
    </div>
  );
}

function readPersonalization(): PersonalizationState {
  try { return { ...defaultPersonalization, ...JSON.parse(localStorage.getItem("ids-prototype-personalization") ?? "{}") }; }
  catch { return defaultPersonalization; }
}

function readThemePreference(): ThemePreference {
  const value = localStorage.getItem("ids-prototype-theme");
  return value === "light" || value === "dark" || value === "system" ? value : "system";
}

function readFontScale(): FontScale {
  const value = localStorage.getItem("ids-prototype-font-scale");
  return value === "compact" || value === "comfortable" ? value : "default";
}

function readHelpLanguage(): HelpLanguage {
  return localStorage.getItem("ids-help-language") === "zh" ? "zh" : "en";
}

const defaultLlmSettings: LlmSettings = {
  baseUrl: "https://api.openai.com/v1",
  model: "gpt-4.1-mini",
  apiKeyConfigured: false,
};

function llmSettingsFromRuntime(settings: Partial<import("./types").RuntimeSettings>): LlmSettings {
  return {
    baseUrl: settings.llmBaseUrl || defaultLlmSettings.baseUrl,
    model: settings.llmModel || defaultLlmSettings.model,
    apiKeyConfigured: settings.llmApiKeyConfigured === true,
  };
}

function useSystemDarkMode(): boolean {
  const getPreference = () => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
  const [matches, setMatches] = useState(getPreference);
  useEffect(() => {
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!media) return undefined;
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener?.("change", update);
    return () => media.removeEventListener?.("change", update);
  }, []);
  return matches;
}
