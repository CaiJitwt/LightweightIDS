import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  BellRing,
  BriefcaseBusiness,
  ChevronLeft,
  ChevronRight,
  Gauge,
  Globe,
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
import type { CaptureStatus, FontScale, LlmSettings, ThemePreference } from "./types";
import brandMascot from "./assets/anime-brand-icon.png";
import { CommandPalette } from "./components/CommandPalette";
import { loadPersonalization, savePersonalization, defaultPersonalization } from "./data/personalizationStore";
import type { PersonalizationState } from "./data/personalizationStore";

import { idsApi } from "./api/idsApi";
import { LocaleContext, resolveLocale, useLocale, useSetLocale, useT } from "./i18n/context";
import type { Locale } from "./i18n/context";

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

const DATA_REFRESH_INTERVAL_MS = 5_000;

type PageKey = "dashboard" | "traffic" | "hosts" | "alerts" | "investigations" | "assets" | "rules" | "reports" | "timeline" | "topology" | "security-events" | "health" | "endpoint" | "settings" | "personalization" | "help";

const navItemKeys: { key: PageKey; icon: typeof Gauge; labelKey: "nav.dashboard" | "nav.traffic" | "nav.hosts" | "nav.alerts" | "nav.investigations" | "nav.assets" | "nav.rules" | "nav.reports" | "nav.timeline" | "nav.topology" | "nav.securityEvents" | "nav.health" | "nav.endpoint" | "nav.settings" | "nav.personalization" | "nav.help" }[] = [
  { key: "dashboard", icon: Gauge, labelKey: "nav.dashboard" },
  { key: "traffic", icon: Activity, labelKey: "nav.traffic" },
  { key: "hosts", icon: Network, labelKey: "nav.hosts" },
  { key: "alerts", icon: BellRing, labelKey: "nav.alerts" },
  { key: "investigations", icon: BriefcaseBusiness, labelKey: "nav.investigations" },
  { key: "assets", icon: Package, labelKey: "nav.assets" },
  { key: "rules", icon: SlidersHorizontal, labelKey: "nav.rules" },
  { key: "reports", icon: Timeline, labelKey: "nav.reports" },
  { key: "timeline", icon: Timeline, labelKey: "nav.timeline" },
  { key: "topology", icon: Waypoints, labelKey: "nav.topology" },
  { key: "security-events", icon: ScrollText, labelKey: "nav.securityEvents" },
  { key: "health", icon: HeartPulse, labelKey: "nav.health" },
  { key: "endpoint", icon: ShieldCheck, labelKey: "nav.endpoint" },
  { key: "settings", icon: Settings, labelKey: "nav.settings" },
  { key: "personalization", icon: Palette, labelKey: "nav.personalization" },
  { key: "help", icon: CircleHelp, labelKey: "nav.help" },
];

const pageMetaKey: Record<PageKey, { titleKey: string; subtitleKey: string }> = {
  dashboard: { titleKey: "page.dashboard", subtitleKey: "meta.dashboard" },
  traffic: { titleKey: "page.traffic", subtitleKey: "meta.traffic" },
  hosts: { titleKey: "page.hosts", subtitleKey: "meta.hosts" },
  alerts: { titleKey: "page.alerts", subtitleKey: "meta.alerts" },
  investigations: { titleKey: "page.investigations", subtitleKey: "meta.investigations" },
  assets: { titleKey: "page.assets", subtitleKey: "meta.assets" },
  rules: { titleKey: "page.rules", subtitleKey: "meta.rules" },
  reports: { titleKey: "page.reports", subtitleKey: "meta.reports" },
  timeline: { titleKey: "page.timeline", subtitleKey: "meta.timeline" },
  topology: { titleKey: "page.topology", subtitleKey: "meta.topology" },
  "security-events": { titleKey: "page.securityEvents", subtitleKey: "meta.securityEvents" },
  health: { titleKey: "page.health", subtitleKey: "meta.health" },
  endpoint: { titleKey: "page.endpoint", subtitleKey: "meta.endpoint" },
  settings: { titleKey: "page.settings", subtitleKey: "meta.settings" },
  personalization: { titleKey: "page.personalization", subtitleKey: "meta.personalization" },
  help: { titleKey: "page.help", subtitleKey: "meta.help" },
};

function AppShell() {
  const t = useT();
  const setLocale = useSetLocale();
  const locale = useLocale();
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

  const [openAlertCount, setOpenAlertCount] = useState(0);
  const [alertBadgeRefresh, setAlertBadgeRefresh] = useState(0);
  const [selectedAlertId, setSelectedAlertId] = useState<number | undefined>();
  const [sensorStatus, setSensorStatus] = useState<CaptureStatus | null>(null);
  const [commandOpen, setCommandOpen] = useState(false);
  const [manualRefreshVersion, setManualRefreshVersion] = useState(0);

  useEffect(() => {
    let active = true;
    const poll = () => {
      idsApi.status().then((status) => { if (active) setSensorStatus(status); }).catch(() => { if (active) setSensorStatus(null); });
    };
    poll();
    const timer = window.setInterval(poll, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

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
      idsApi.saveSettings({ themePreference, fontScale, locale }).catch(() => undefined);
    }, 180);
    return () => window.clearTimeout(timer);
  }, [fontScale, runtimeSettingsLoaded, themePreference, locale]);

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
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(
      () => setRefreshVersion((value) => value + 1),
      DATA_REFRESH_INTERVAL_MS,
    );
    return () => window.clearInterval(timer);
  }, [autoRefresh]);

  useEffect(() => {
    const openCommandPalette = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      }
    };
    window.addEventListener("keydown", openCommandPalette);
    return () => window.removeEventListener("keydown", openCommandPalette);
  }, []);

  const notifyDataChanged = useCallback(() => {
    setRefreshVersion((value) => value + 1);
    setAlertBadgeRefresh((value) => value + 1);
  }, []);

  const refreshCurrentView = useCallback(() => {
    setManualRefreshVersion((value) => value + 1);
    notifyDataChanged();
  }, [notifyDataChanged]);

  const commandActions = useMemo(() => [
    ...navItemKeys.map(({ key, labelKey, icon: Icon }) => ({
      key: `page:${key}`,
      label: t(labelKey),
      category: t("command.navigate"),
      icon: <Icon size={16} />,
    })),
    { key: "action:refresh", label: t("app.refresh"), category: t("command.navigate"), icon: <RefreshCw size={16} /> },
    {
      key: "action:theme",
      label: theme === "light" ? t("app.themeDark") : t("app.themeLight"),
      category: "Appearance",
      icon: theme === "light" ? <Moon size={16} /> : <Sun size={16} />,
    },
  ], [theme, t]);

  const runCommand = useCallback((key: string) => {
    if (key.startsWith("page:")) {
      const target = key.slice(5) as PageKey;
      if (target in pageMetaKey) setPage(target);
      return;
    }
    if (key === "action:refresh") refreshCurrentView();
    if (key === "action:theme") setThemePreference(theme === "light" ? "dark" : "light");
  }, [refreshCurrentView, theme]);

  const metaKey = pageMetaKey[page];

  const themeTitle = themePreference === "system" ? t("app.themeSystem") : themePreference === "dark" ? t("app.themeDark") : t("app.themeLight");

  const sensorOnline = sensorStatus?.state === "running";

  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}${personalization.background ? " has-wallpaper" : ""}`} data-theme={theme} data-font-scale={fontScale} lang={locale} style={{
      "--accent": personalization.accent,
      "--component-tint": personalization.componentTint,
      "--component-opacity": `${personalization.componentOpacity}%`,
      "--component-blur": `${personalization.componentBlur}px`,
      "--table-tint": personalization.tableTint,
      "--table-opacity": `${personalization.tableOpacity}%`,
      "--table-blur": `${personalization.tableBlur}px`,
    } as React.CSSProperties}>
      {personalization.background && createPortal(<div className="workspace-wallpaper" data-testid="workspace-wallpaper" style={{ backgroundImage: `url(${personalization.background})`, backgroundSize: personalization.backgroundSize === "stretch" ? "100% 100%" : personalization.backgroundSize === "original" ? "auto" : personalization.backgroundSize, backgroundPosition: personalization.backgroundPosition, opacity: personalization.backgroundOpacity / 100 }} />, document.body)}
      <aside className="sidebar">
        <div className="brand-block"><span className="brand-mark"><img src={brandMascot} alt="" /></span><span className="brand-copy"><strong>{t("app.brand")}</strong><small>{t("app.tagline")}</small></span></div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {navItemKeys.map((item) => {
            const Icon = item.icon;
            const label = t(item.labelKey);
            const badge = item.key === "alerts" && openAlertCount > 0 ? (openAlertCount > 99 ? "99+" : openAlertCount) : null;
            return <button type="button" key={item.key} className={page === item.key ? "active" : ""} onClick={() => setPage(item.key)} title={collapsed ? label : undefined}><Icon size={18} /><span>{label}</span>{badge !== null && <b title={`${openAlertCount} unconfirmed alerts`}>{badge}</b>}</button>;
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="sensor-summary"><span className={`live-dot${!sensorOnline ? " paused" : ""}`} /><span>{sensorOnline ? <><strong>{t("app.sensorOnline")}</strong><small>{sensorStatus?.interface || ""} &middot; {(sensorStatus?.packetsPerSecond ?? 0) > 1000 ? `${((sensorStatus?.packetsPerSecond ?? 0) / 1000).toFixed(1)}k` : (sensorStatus?.packetsPerSecond ?? 0)} pkt/s</small></> : <><strong>{t("app.sensorIdle")}</strong><small>{sensorStatus ? t("app.captureStopped") : t("app.apiUnavailable")}</small></>}</span></div>
          <button type="button" className="collapse-button" onClick={() => setCollapsed((value) => !value)} title={collapsed ? t("app.expand") : t("app.collapse")}>{collapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}<span>{t("app.collapse")}</span></button>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="page-heading"><h1>{t(metaKey.titleKey as Parameters<typeof t>[0])}</h1><p>{t(metaKey.subtitleKey as Parameters<typeof t>[0])}</p></div>
          <div className="topbar-actions">
            <button className="global-search" type="button" aria-label={t("command.placeholder")} aria-haspopup="dialog" aria-expanded={commandOpen} onClick={() => setCommandOpen(true)}><Search size={16} /><span>{t("app.search")}</span><kbd>Ctrl K</kbd></button>
            <label className="refresh-toggle"><input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} /><span>{t("app.autoRefresh")}</span></label>
            <button className="icon-button" type="button" title={t("app.refresh")} onClick={refreshCurrentView}><RefreshCw size={17} /></button>
            <button className="icon-button" type="button" title={themeTitle} onClick={() => setThemePreference(themePreference === "system" ? "dark" : themePreference === "dark" ? "light" : "system")}>{themePreference === "system" ? <MonitorCog size={17} /> : themePreference === "dark" ? <Moon size={17} /> : <Sun size={17} />}</button>
            <button className="icon-text-button" type="button" title={t("app.language")} onClick={() => setLocale(locale === "en" ? "zh" : "en")}><Globe size={15} /><span style={{ fontSize: 11, fontWeight: 600 }}>{locale === "en" ? "EN" : "中文"}</span></button>
            <button className="user-button" type="button" title={t("app.user")} onClick={() => setPage("settings")}><Laptop size={16} /><span>{t("app.user")}</span></button>
          </div>
        </header>
        <div className="page-content" data-manual-refresh-version={manualRefreshVersion} data-refresh-version={refreshVersion}>
          <Suspense key={`${page}:${manualRefreshVersion}`} fallback={<div className="page-loading">{t("common.loadingView")}</div>}>
            {page === "dashboard" && <DashboardPage refreshVersion={refreshVersion} onStatisticsReset={notifyDataChanged} onOpenAlertCountChange={setOpenAlertCount} onOpenAlerts={() => setPage("alerts")} onOpenHost={(ip) => { setSelectedHostIp(ip); setPage("hosts"); }} />}
            {page === "traffic" && <TrafficPage onDataChanged={notifyDataChanged} />}
            {page === "hosts" && <HostsPage initialHostIp={selectedHostIp} refreshVersion={refreshVersion} />}
            {page === "alerts" && <AlertsPage llmSettings={llmSettings} refreshVersion={refreshVersion} initialAlertId={selectedAlertId} onAlertsChanged={notifyDataChanged} />}
            {page === "investigations" && <InvestigationsPage refreshVersion={refreshVersion} />}
            {page === "assets" && <AssetsPage refreshVersion={refreshVersion} />}
            {page === "rules" && <RulesPage refreshVersion={refreshVersion} />}
            {page === "reports" && <ReportsPage refreshVersion={refreshVersion} />}
            {page === "timeline" && <EventTimelinePage refreshVersion={refreshVersion} />}
            {page === "topology" && <NetworkTopologyPage refreshVersion={refreshVersion} />}
            {page === "security-events" && <SecurityEventsPage onOpenAlert={(alertId) => { setSelectedAlertId(alertId); setPage("alerts"); }} />}
            {page === "health" && <SystemHealthPage refreshVersion={refreshVersion} />}
            {page === "endpoint" && <EndpointSecurityPage refreshVersion={refreshVersion} />}
            {page === "settings" && <SettingsPage themePreference={themePreference} onThemePreferenceChange={setThemePreference} fontScale={fontScale} onFontScaleChange={setFontScale} llmSettings={llmSettings} onLlmSettingsChange={setLlmSettings} />}
            {page === "personalization" && <PersonalizationPage state={personalization} onChange={setPersonalization} storageWarning={storageWarning} persistWarning={persistWarning} />}
            {page === "help" && <HelpPage onNavigate={setPage} language={locale} onLanguageChange={setLocale} />}
          </Suspense>
        </div>
      </main>
      <CommandPalette open={commandOpen} onClose={() => setCommandOpen(false)} actions={commandActions} onSelect={runCommand} />
      {personalization.petImage && <img className={`overlay-pet ${personalization.petPosition}`} src={personalization.petImage} alt="" style={{ width: personalization.petSize, opacity: personalization.petOpacity / 100 }} />}
    </div>
  );
}

export default function App() {
  const [locale, setLocale] = useState<Locale>(resolveLocale);
  useEffect(() => {
    localStorage.setItem("ids-prototype-locale", locale);
    document.documentElement.lang = locale;
  }, [locale]);
  return (
    <LocaleContext.Provider value={{ locale, setLocale }}>
      <AppShell />
    </LocaleContext.Provider>
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
    const checkBrowser = () => setMatches(mql.matches);
    checkBrowser();
    mql.addEventListener("change", checkBrowser);
    window.addEventListener("focus", checkBrowser);

    const poll = async () => {
      checkBrowser();
      try {
        const { dark } = await idsApi.systemTheme();
        setMatches(dark);
      } catch { /* backend unavailable — keep browser value */ }
    };
    const interval = window.setInterval(poll, 2000);
    poll();
    return () => {
      mql.removeEventListener("change", checkBrowser);
      window.removeEventListener("focus", checkBrowser);
      window.clearInterval(interval);
    };
  }, []);
  return matches;
}
