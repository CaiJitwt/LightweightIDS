import { lazy, Suspense, useEffect, useState } from "react";
import {
  Activity,
  BellRing,
  ChevronLeft,
  ChevronRight,
  Gauge,
  Laptop,
  Moon,
  Network,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Sun,
} from "lucide-react";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((module) => ({ default: module.DashboardPage })));
const TrafficPage = lazy(() => import("./pages/TrafficPage").then((module) => ({ default: module.TrafficPage })));
const HostsPage = lazy(() => import("./pages/HostsPage").then((module) => ({ default: module.HostsPage })));
const AlertsPage = lazy(() => import("./pages/AlertsPage").then((module) => ({ default: module.AlertsPage })));

type PageKey = "dashboard" | "traffic" | "hosts" | "alerts";

const navItems = [
  { key: "dashboard" as const, label: "Dashboard", icon: Gauge },
  { key: "traffic" as const, label: "Traffic Monitor", icon: Activity },
  { key: "hosts" as const, label: "Host Explorer", icon: Network },
  { key: "alerts" as const, label: "Alert Center", icon: BellRing, count: 9 },
];

const pageMeta: Record<PageKey, { title: string; subtitle: string }> = {
  dashboard: { title: "Security overview", subtitle: "Current network posture and analyst priorities" },
  traffic: { title: "Traffic monitor", subtitle: "Live packet metadata from the active capture interface" },
  hosts: { title: "Host explorer", subtitle: "Observed assets, connections and composite risk" },
  alerts: { title: "Alert center", subtitle: "Review evidence, related packets and analyst status" },
};

export default function App() {
  const [page, setPage] = useState<PageKey>("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => localStorage.getItem("ids-prototype-theme") === "dark" ? "dark" : "light");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    localStorage.setItem("ids-prototype-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (!autoRefresh || page !== "dashboard") return undefined;
    const timer = window.setInterval(() => setRefreshVersion((value) => value + 1), 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, page]);

  const meta = pageMeta[page];

  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`} data-theme={theme}>
      <aside className="sidebar">
        <div className="brand-block"><span className="brand-mark"><Shield size={20} /></span><span className="brand-copy"><strong>Lightweight IDS</strong><small>Analyst console</small></span></div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            return <button type="button" key={item.key} className={page === item.key ? "active" : ""} onClick={() => setPage(item.key)} title={collapsed ? item.label : undefined}><Icon size={18} /><span>{item.label}</span>{item.count && <b>{item.count}</b>}</button>;
          })}
        </nav>
        <div className="sidebar-footer">
          <div className="sensor-summary"><span className="live-dot" /><span><strong>Sensor online</strong><small>Ethernet 3 - 1.2k pkt/min</small></span></div>
          <button type="button" className="nav-utility" title="Settings"><Settings size={18} /><span>Settings</span></button>
          <button type="button" className="collapse-button" onClick={() => setCollapsed((value) => !value)} title={collapsed ? "Expand sidebar" : "Collapse sidebar"}>{collapsed ? <ChevronRight size={17} /> : <ChevronLeft size={17} />}<span>Collapse</span></button>
        </div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="page-heading"><h1>{meta.title}</h1><p>{meta.subtitle}</p></div>
          <div className="topbar-actions">
            <button className="global-search" type="button"><Search size={16} /><span>Search</span><kbd>Ctrl K</kbd></button>
            {page === "dashboard" && <label className="refresh-toggle"><input type="checkbox" checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} /><span>Auto-refresh</span></label>}
            <button className="icon-button" type="button" title="Refresh current view" onClick={() => setRefreshVersion((value) => value + 1)}><RefreshCw size={17} /></button>
            <button className="icon-button" type="button" title={`Use ${theme === "light" ? "dark" : "light"} theme`} onClick={() => setTheme((value) => value === "light" ? "dark" : "light")}>{theme === "light" ? <Moon size={17} /> : <Sun size={17} />}</button>
            <button className="user-button" type="button" title="Analyst profile"><Laptop size={16} /><span>Analyst</span></button>
          </div>
        </header>
        <div className="page-content">
          <Suspense fallback={<div className="page-loading">Loading view...</div>}>
            {page === "dashboard" && <DashboardPage refreshVersion={refreshVersion} onOpenAlerts={() => setPage("alerts")} />}
            {page === "traffic" && <TrafficPage />}
            {page === "hosts" && <HostsPage />}
            {page === "alerts" && <AlertsPage />}
          </Suspense>
        </div>
      </main>
    </div>
  );
}
