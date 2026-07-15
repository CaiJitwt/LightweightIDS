import { useEffect, useState } from "react";
import { Activity, BellRing, Radio, RotateCcw, ShieldCheck, TriangleAlert } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import { alerts, hosts, severityDistribution, trendData } from "../data/mockData";
import type { DashboardSnapshot } from "../types";

interface DashboardPageProps {
  onOpenAlerts: () => void;
  onOpenHost: (ip: string) => void;
  onOpenAlertCountChange: (count: number) => void;
  onStatisticsReset: () => void;
  refreshVersion: number;
}

const previewSnapshot: DashboardSnapshot = {
  capture: {
    state: "stopped",
    interface: "Offline preview",
    filterExpression: "",
    savePackets: false,
    detectionEnabled: true,
    packetTotal: 0,
    alertTotal: 0,
    skippedTotal: 0,
    savedPacketTotal: 0,
    savedAlertTotal: 0,
    packetsPerSecond: 0,
    error: "",
    nextSequence: 0,
  },
  statistics: { packetTotal: 0, alertTotal: 0, openAlerts: 0, highPriorityAlerts: 0, highRiskHosts: 0, lastHourPackets: 0 },
  trend: [],
  severityDistribution: [],
  highRiskHosts: [],
  recentAlerts: [],
};

export function DashboardPage({ onOpenAlerts, onOpenHost, onOpenAlertCountChange, onStatisticsReset, refreshVersion }: DashboardPageProps) {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(previewSnapshot);
  const [connected, setConnected] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetNotice, setResetNotice] = useState("");

  useEffect(() => {
    let active = true;
    idsApi.dashboard()
      .then((next) => {
        if (!active) return;
        setSnapshot(next);
        setConnected(true);
        onOpenAlertCountChange(next.statistics.openAlerts);
      })
      .catch(() => {
        if (active) setConnected(false);
      });
    return () => { active = false; };
  }, [onOpenAlertCountChange, refreshVersion]);

  const captureLive = snapshot.capture.state === "running";
  const dataLabel = connected ? "Local SQLite data" : "Offline preview";
  const resetStatistics = async () => {
    if (!window.confirm("Delete all packet, alert, and security-event runtime data and start from zero? Assets, investigations, and evidence snapshots will be preserved.")) return;
    setResetting(true);
    setResetNotice("");
    try {
      const result = await idsApi.resetStatistics();
      setSnapshot(result.dashboard);
      setConnected(true);
      onOpenAlertCountChange(result.dashboard.statistics.openAlerts);
      onStatisticsReset();
      setResetNotice("Packet, alert, and security-event runtime data reset. New activity will start from zero.");
    } catch (error) {
      setResetNotice(error instanceof Error ? error.message : "Statistics could not be reset.");
    } finally {
      setResetting(false);
    }
  };
  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <section className="dashboard-toolbar">
        <span>{resetNotice || `${dataLabel} is active.`}</span>
        <button className="danger-button" type="button" disabled={!connected || resetting} onClick={() => void resetStatistics()} title={connected ? "Reset persisted statistics" : "Start the local API to reset statistics"}><RotateCcw size={15} />{resetting ? "Resetting..." : "Reset statistics"}</button>
      </section>
      <section className="metric-strip" aria-label="Current IDS statistics">
        <Metric icon={<Radio size={18} />} label="Capture status" value={captureLive ? "Live" : titleCase(snapshot.capture.state)} meta={snapshot.capture.interface || "No active interface"} tone={captureLive ? "green" : "blue"} />
        <Metric icon={<Activity size={18} />} label="Packets observed" value={formatNumber(snapshot.statistics.packetTotal)} meta={`${formatNumber(snapshot.statistics.lastHourPackets)} in latest hour`} tone="blue" />
        <Metric icon={<BellRing size={18} />} label="Open alerts" value={formatNumber(snapshot.statistics.openAlerts)} meta={`${formatNumber(snapshot.statistics.highPriorityAlerts)} high priority`} tone="amber" />
        <Metric icon={<TriangleAlert size={18} />} label="High-risk hosts" value={formatNumber(snapshot.statistics.highRiskHosts)} meta="Composite risk score of 70 or higher" tone="red" />
      </section>

      <section className="analysis-grid">
        <div className="section-panel trend-panel">
          <SectionHeading title="Traffic and alert trend" meta={`${dataLabel} - last 12 observed hours`} />
          <div className="chart-area" aria-label="Traffic and alert trend chart">
            {snapshot.trend.length ? <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={snapshot.trend} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Area type="monotone" dataKey="packets" stroke="#2878d0" fill="#dcecff" strokeWidth={2} isAnimationActive={false} />
                <Area type="monotone" dataKey="alerts" stroke="#c2413b" fill="#fde2e0" strokeWidth={2} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer> : <EmptyState text="No traffic or alerts have been stored yet." />}
          </div>
        </div>

        <div className="section-panel severity-panel">
          <SectionHeading title="Severity distribution" meta={`${formatNumber(snapshot.statistics.alertTotal)} persisted alerts`} />
          <div className="chart-area" aria-label="Severity distribution chart">
            {snapshot.severityDistribution.length ? <ResponsiveContainer width="100%" height="100%">
              <BarChart data={snapshot.severityDistribution} layout="vertical" margin={{ top: 8, right: 16, left: 8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--chart-grid)" />
                <XAxis type="number" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={56} tick={{ fontSize: 11 }} />
                <Tooltip cursor={{ fill: "var(--hover)" }} contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>
                  {snapshot.severityDistribution.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer> : <EmptyState text="No alerts have been stored yet." />}
          </div>
        </div>
      </section>

      <section className="dashboard-lower">
        <div className="section-panel host-risk-panel">
          <SectionHeading title="High-risk hosts" meta="Prioritized by composite risk" />
          <div className="compact-list">
            {snapshot.highRiskHosts.length ? snapshot.highRiskHosts.slice(0, 4).map((host) => (
              <button className="risk-row button-row" type="button" key={host.ip} onClick={() => onOpenHost(host.ip)}>
                <div className="host-identity">
                  <span className="host-avatar">{host.name.slice(0, 2).toUpperCase()}</span>
                  <span><strong>{host.name}</strong><small>{host.ip} - {host.role}</small></span>
                </div>
                <span className={`risk-score risk-${host.risk >= 80 ? "high" : host.risk >= 50 ? "medium" : "low"}`}>{host.risk}</span>
                <span className="host-alert-count">{host.alerts} alerts</span>
              </button>
            )) : <EmptyState text="No host risk signals are available yet." />}
          </div>
        </div>

        <div className="section-panel recent-alerts-panel">
          <SectionHeading
            title="Recent alerts"
            meta="Analyst review queue"
            action={<button className="text-button" type="button" onClick={onOpenAlerts}>Open Alert Center</button>}
          />
          <div className="compact-list">
            {snapshot.recentAlerts.length ? snapshot.recentAlerts.slice(0, 4).map((alert) => (
              <button className="alert-row" type="button" key={alert.id} onClick={onOpenAlerts}>
                <SeverityBadge severity={alert.severity} />
                <span><strong>{alert.ruleName}</strong><small>{alert.source} to {alert.destination}</small></span>
                <time>{alert.timestamp}</time>
              </button>
            )) : <EmptyState text="No alerts have been stored yet." />}
          </div>
        </div>
      </section>

      <div className="system-note"><ShieldCheck size={15} /> HTTPS payload remains encrypted; TLS items show metadata and fingerprint risk only.</div>
    </div>
  );
}

function Metric({ icon, label, value, meta, tone }: { icon: React.ReactNode; label: string; value: string; meta: string; tone: string }) {
  return <div className={`metric metric-${tone}`}><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value}</strong><small>{meta}</small></div></div>;
}

function SectionHeading({ title, meta, action }: { title: string; meta: string; action?: React.ReactNode }) {
  return <header className="section-heading"><div><h2>{title}</h2><p>{meta}</p></div>{action}</header>;
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty-state">{text}</p>;
}

function formatNumber(value: number) {
  return new Intl.NumberFormat().format(value);
}

function titleCase(value: string) {
  return value ? `${value[0].toUpperCase()}${value.slice(1)}` : "Unknown";
}
