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
  MonitorCog,
  Moon,
  Network,
  Package,
  Palette,
  RefreshCw,
  Search,
  ScrollText,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  Sun,
  Timeline,
  Waypoints,
} from "lucide-react";
import type { FontScale, LlmSettings, ThemePreference } from "./types";
import brandMascot from "./assets/anime-brand-icon.png";
import { loadPersonalization, savePersonalization, defaultPersonalization } from "./data/personalizationStore";
import type { PersonalizationState } from "./data/personalizationStore";
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
  personalization: { title: "Personalization", subtitle: "Workspace surfaces, wallpaper and overlay companion" },
  help: { title: "Help center", subtitle: "Product guidance, analyst workflow and quick navigation" },
};

export default function App() {
  const [page, setPage] = useState<PageKey>("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => readThemePreference());
  const [fontScale, setFontScale] = useState<FontScale>(() => readFontScale());
  const systemDark = useSystemDarkMode();
  const theme = themePreference === "system" ? (systemDark ? "dark" : "light") : themePreference;
  const [llmSettings, setLlmSettings] = useState<LlmSettings>(defaultLlmSettings);
  const [runtimeSettingsLoaded, setRuntimeSettingsLoaded] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [selectedHostIp, setSelectedHostIp] = useState<string | undefined>();
  const [personalization, setPersonalization] = useState<PersonalizationState>(defaultPersonalization);
  const [personalizationLoaded, setPersonalizationLoaded] = useState(false);
  const [persistWarning, setPersistWarning] = useState(false);
  const [storageWarning, setStorageWarning] = useState(false);
  const [helpLanguage, setHelpLanguage] = useState<HelpLanguage>(readHelpLanguage);
  const [openAlertCount, setOpenAlertCount] = useState(0);
  const [alertBadgeRefresh, setAlertBadgeRefresh] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<number | undefined>();

  useEffect(() => {
    localStorage.setItem("ids-prototype-theme", themePreference);
  }, [themePreference]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem("ids-prototype-font-scale", fontScale);
  }, [fontScale]);

  useEffect(() => {
    let active = true;
    localStorage.removeItem("ids-prototype-llm");
    sessionStorage.removeItem("ids-prototype-llm-api-key");
    idsApi.settings()
      .then((settings) => {
        if (!active) return;
        setLlmSettings(llmSettingsFromRuntime(settings));
        if (settings.themePreference === "system" || settings.themePreference === "light" || settings.themePreference === "dark") {
          setThemePreference(settings.themePreference);
        }
        if (settings.fontScale === "compact" || settings.fontScale === "default" || settings.fontScale === "comfortable") {
          setFontScale(settings.fontScale);
        }
        setRuntimeSettingsLoaded(true);
      })
      .catch(() => undefined);
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!runtimeSettingsLoaded) return undefined;
    const timer = window.setTimeout(() => {
      idsApi.saveSettings({ themePreference, fontScale }).catch(() => undefined);
    }, 180);
    return () => window.clearTimeout(timer);
  }, [fontScale, runtimeSettingsLoaded, themePreference]);

  useEffect(() => {
    let active = true;
    loadPersonalization().then(([state, corrupted]) => {
      if (active) {
        setPersonalization(state);
        setPersistWarning(corrupted);
        setPersonalizationLoaded(true);
      }
    }).catch(() => {
      if (active) {
        setPersistWarning(true);
        setPersonalizationLoaded(true);
      }
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!personalizationLoaded) return undefined;
    let active = true;
    const timer = window.setTimeout(() => {
      savePersonalization(personalization).then(() => { if (active) setStorageWarning(false); })
        .catch(() => { if (active) setStorageWarning(true); });
    }, 180);
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [personalization, personalizationLoaded]);

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
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}${personalization.background ? " has-wallpaper" : ""}`} data-theme={theme} data-font-scale={fontScale} style={{
      "--accent": personalization.accent,
      "--component-tint": personalization.componentTint,
      "--component-opacity": `${personalization.componentOpacity}%`,
      "--component-blur": `${personalization.componentBlur}px`,
      "--table-tint": personalization.tableTint,
      "--table-opacity": `${personalization.tableOpacity}%`,
      "--table-blur": `${personalization.tableBlur}px`,
    } as React.CSSProperties}>
      {personalization.background && <div className="workspace-wallpaper" data-testid="workspace-wallpaper" style={{ backgroundImage: `url(${personalization.background})`, backgroundSize: personalization.backgroundSize === "stretch" ? "100% 100%" : personalization.backgroundSize === "original" ? "auto" : personalization.backgroundSize, backgroundPosition: personalization.backgroundPosition, opacity: personalization.backgroundOpacity / 100 }} />}
      <aside className="sidebar">
        <div className="brand-block"><span className="brand-mark"><img src={brandMascot} alt="" /></span><span className="brand-copy"><strong>Lightweight IDS</strong><small>Analyst console</small></span></div>
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
            <button className="icon-button" type="button" title={themePreference === "system" ? "Following system — click for dark" : themePreference === "dark" ? "Switch to light theme" : "Switch to system theme"} onClick={() => setThemePreference(themePreference === "system" ? "dark" : themePreference === "dark" ? "light" : "system")}>{themePreference === "system" ? <MonitorCog size={17} /> : themePreference === "dark" ? <Moon size={17} /> : <Sun size={17} />}</button>
            <button className="user-button" type="button" title="Analyst profile"><Laptop size={16} /><span>Analyst</span></button>
          </div>
        </header>
        <div className="page-content">
          <Suspense fallback={<div className="page-loading">Loading view...</div>}>
            {page === "dashboard" && <DashboardPage refreshVersion={refreshVersion} onStatisticsReset={() => { setRefreshVersion((value) => value + 1); setAlertBadgeRefresh((value) => value + 1); }} onOpenAlertCountChange={setOpenAlertCount} onOpenAlerts={() => setPage("alerts")} onOpenHost={(ip) => { setSelectedHostIp(ip); setPage("hosts"); }} />}
            {page === "traffic" && <TrafficPage onDataChanged={() => { setRefreshVersion((value) => value + 1); setAlertBadgeRefresh((value) => value + 1); }} />}
            {page === "hosts" && <HostsPage initialHostIp={selectedHostIp} refreshVersion={refreshVersion} />}
            {page === "alerts" && <AlertsPage llmSettings={llmSettings} refreshVersion={refreshVersion} initialAlertId={selectedAlertId} onAlertsChanged={() => setAlertBadgeRefresh((value) => value + 1)} />}
            {page === "investigations" && <InvestigationsPage />}
            {page === "assets" && <AssetsPage />}
            {page === "rules" && <RulesPage />}
            {page === "reports" && <ReportsPage refreshVersion={refreshVersion} />}
            {page === "timeline" && <EventTimelinePage refreshVersion={refreshVersion} />}
            {page === "topology" && <NetworkTopologyPage refreshVersion={refreshVersion} />}
            {page === "security-events" && <SecurityEventsPage onOpenAlert={(alertId) => { setSelectedAlertId(alertId); setPage("alerts"); }} />}
            {page === "health" && <SystemHealthPage refreshVersion={refreshVersion} />}
            {page === "endpoint" && <EndpointSecurityPage refreshVersion={refreshVersion} />}
            {page === "settings" && <SettingsPage themePreference={themePreference} onThemePreferenceChange={setThemePreference} fontScale={fontScale} onFontScaleChange={setFontScale} llmSettings={llmSettings} onLlmSettingsChange={setLlmSettings} />}
            {page === "personalization" && <PersonalizationPage state={personalization} onChange={setPersonalization} storageWarning={storageWarning} persistWarning={persistWarning} />}
            {page === "help" && <HelpPage onNavigate={setPage} language={helpLanguage} onLanguageChange={setHelpLanguage} />}
          </Suspense>
        </div>
      </main>
      {personalization.petImage && <img className={`overlay-pet ${personalization.petPosition}`} src={personalization.petImage} alt="" style={{ width: personalization.petSize, opacity: personalization.petOpacity / 100 }} />}
    </div>
  );
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
  const [matches, setMatches] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ?? false);
  useEffect(() => {
    const mql = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mql) return;
    const check = () => setMatches(mql.matches);
    check();
    mql.addEventListener("change", check);
    window.addEventListener("focus", check);
    const interval = window.setInterval(check, 2000);
    return () => {
      mql.removeEventListener("change", check);
      window.removeEventListener("focus", check);
      window.clearInterval(interval);
    };
  }, []);
  return matches;
}
