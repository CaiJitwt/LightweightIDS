import { useEffect, useState } from "react";
import { Activity, BellRing, Radio, RotateCcw, ShieldCheck, TriangleAlert } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
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
  const t = useT();
  const [snapshot, setSnapshot] = useState<DashboardSnapshot>(previewSnapshot);
  const [connected, setConnected] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [resetNotice, setResetNotice] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    idsApi.dashboard()
      .then((next) => {
        if (!active) return;
        setSnapshot(next);
        setConnected(true);
        setLoading(false);
        onOpenAlertCountChange(next.statistics.openAlerts);
      })
      .catch(() => {
        if (active) { setConnected(false); setLoading(false); }
      });
    return () => { active = false; };
  }, [onOpenAlertCountChange, refreshVersion]);

  const captureLive = snapshot.capture.state === "running";
  const dataLabel = connected ? t("dashboard.localData") : t("dashboard.offlinePreview");

  if (loading) {
    return <div className="page-stack"><div className="page-loading">{t("common.loading")}</div></div>;
  }
  const detectionRateTrend = snapshot.trend.map((point) => ({
    ...point,
    detectionRate: point.packets > 0 ? Math.round(point.alerts * 10000 / point.packets) / 10 : 0,
  }));
  const detectionRateSamples = detectionRateTrend.filter((point) => point.packets > 0);
  const averageDetectionRate = detectionRateSamples.length
    ? detectionRateSamples.reduce((total, point) => total + point.detectionRate, 0) / detectionRateSamples.length
    : 0;
  const averagePacketCount = snapshot.trend.length
    ? snapshot.trend.reduce((total, point) => total + point.packets, 0) / snapshot.trend.length
    : 0;
  const trendUnit = snapshot.trendBucket === "minute" ? t("dashboard.minutes") : t("dashboard.hours");
  const resetStatistics = async () => {
    if (!window.confirm(t("dashboard.resetConfirm"))) return;
    setResetting(true);
    setResetNotice("");
    try {
      const result = await idsApi.resetStatistics();
      setSnapshot(result.dashboard);
      setConnected(true);
      onOpenAlertCountChange(result.dashboard.statistics.openAlerts);
      onStatisticsReset();
      setResetNotice(t("dashboard.resetDone"));
    } catch (error) {
      setResetNotice(error instanceof Error ? error.message : t("dashboard.resetFailed"));
    } finally {
      setResetting(false);
    }
  };
  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <section className="dashboard-toolbar">
        <span>{resetNotice || t("dashboard.dataActive", { label: dataLabel })}</span>
        <button className="danger-button" type="button" disabled={!connected || resetting} onClick={() => void resetStatistics()} title={connected ? t("dashboard.resetTitle") : t("dashboard.resetDisabled")}><RotateCcw size={15} />{resetting ? t("dashboard.resetting") : t("dashboard.resetStatistics")}</button>
      </section>
      <section className="metric-strip" aria-label="Current IDS statistics">
        <Metric icon={<Radio size={18} />} label={t("dashboard.captureStatus")} value={captureLive ? t("dashboard.live") : titleCase(snapshot.capture.state)} meta={snapshot.capture.interface || t("dashboard.noActiveInterface")} tone={captureLive ? "green" : "blue"} />
        <Metric icon={<Activity size={18} />} label={t("dashboard.packetsObserved")} value={formatNumber(snapshot.statistics.packetTotal)} meta={t("dashboard.inLatestHour", { count: formatNumber(snapshot.statistics.lastHourPackets) })} tone="blue" />
        <Metric icon={<BellRing size={18} />} label={t("dashboard.openAlerts")} value={formatNumber(snapshot.statistics.openAlerts)} meta={t("dashboard.highPriority", { count: formatNumber(snapshot.statistics.highPriorityAlerts) })} tone="amber" />
        <Metric icon={<TriangleAlert size={18} />} label={t("dashboard.highRiskHosts")} value={formatNumber(snapshot.statistics.highRiskHosts)} meta={t("dashboard.riskScore70")} tone="red" />
      </section>

      <section className="analysis-grid">
        <div className="section-panel trend-panel">
          <SectionHeading title={t("dashboard.trafficTrend")} meta={t("dashboard.trafficTrendMeta", { label: dataLabel, unit: trendUnit })} />
          <div className="chart-area" aria-label="Traffic and alert trend chart">
            {snapshot.trend.length ? <ResponsiveContainer width="100%" height="100%">
              <LineChart data={snapshot.trend} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <ReferenceLine y={averagePacketCount} stroke="#d97706" strokeDasharray="5 4" label={{ value: t("dashboard.averageTraffic"), position: "insideTopRight", fill: "#9a5b08", fontSize: 10 }} />
                <Line type="linear" dataKey="packets" name={t("traffic.packets")} stroke="#2878d0" strokeWidth={2.25} dot={false} activeDot={false} isAnimationActive={false} />
                <Line type="linear" dataKey="alerts" name={t("traffic.alerts")} stroke="#c2413b" strokeWidth={2.25} dot={false} activeDot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer> : <EmptyState text={t("dashboard.noTrafficYet")} />}
          </div>
        </div>

        <div className="section-panel severity-panel">
          <SectionHeading title={t("dashboard.severityDistribution")} meta={t("dashboard.persistedAlerts", { count: formatNumber(snapshot.statistics.alertTotal) })} />
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
            </ResponsiveContainer> : <EmptyState text={t("dashboard.noAlertsYet")} />}
          </div>
        </div>
      </section>

      <section className="section-panel detection-rate-panel">
        <SectionHeading title={t("dashboard.detectionRateTrend")} meta={t("dashboard.detectionRateMeta", { unit: trendUnit })} />
        <div className="chart-area" aria-label="Detection rate trend chart">
          {detectionRateTrend.length ? <ResponsiveContainer width="100%" height="100%">
            <LineChart data={detectionRateTrend} margin={{ top: 10, right: 18, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
              <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
              <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
              <Tooltip formatter={(value) => [`${Number(value).toFixed(1)}`, t("dashboard.alertsPer1k")]} contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
              <ReferenceLine y={averageDetectionRate} stroke="#d97706" strokeDasharray="5 4" label={{ value: t("dashboard.average"), position: "insideTopRight", fill: "#9a5b08", fontSize: 10 }} />
              <Line type="linear" dataKey="detectionRate" stroke="#2f8f66" strokeWidth={2.5} dot={false} activeDot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer> : <EmptyState text={t("dashboard.noTrendAvailable")} />}
        </div>
      </section>

      <section className="dashboard-lower">
        <div className="section-panel host-risk-panel">
          <SectionHeading title={t("dashboard.highRiskHostsTitle")} meta={t("dashboard.highRiskMeta")} />
          <div className="compact-list">
            {snapshot.highRiskHosts.length ? snapshot.highRiskHosts.slice(0, 4).map((host) => (
              <button className="risk-row button-row" type="button" key={host.ip} onClick={() => onOpenHost(host.ip)}>
                <div className="host-identity">
                  <span className="host-avatar">{host.name.slice(0, 2).toUpperCase()}</span>
                  <span><strong>{host.name}</strong><small>{host.ip} - {host.role}</small></span>
                </div>
                <span className={`risk-score risk-${host.risk >= 80 ? "high" : host.risk >= 50 ? "medium" : "low"}`}>{host.risk}</span>
                <span className="host-alert-count">{t("dashboard.alertsCount", { count: host.alerts })}</span>
              </button>
            )) : <EmptyState text={t("dashboard.noHostSignals")} />}
          </div>
        </div>

        <div className="section-panel recent-alerts-panel">
          <SectionHeading
            title={t("dashboard.recentAlerts")}
            meta={t("dashboard.analystQueue")}
            action={<button className="text-button" type="button" onClick={onOpenAlerts}>{t("dashboard.openAlertCenter")}</button>}
          />
          <div className="compact-list">
            {snapshot.recentAlerts.length ? snapshot.recentAlerts.slice(0, 4).map((alert) => (
              <button className="alert-row" type="button" key={alert.id} onClick={onOpenAlerts}>
                <SeverityBadge severity={alert.severity} />
                <span><strong>{alert.ruleName}</strong><small>{alert.source} to {alert.destination}</small></span>
                <time>{alert.timestamp}</time>
              </button>
            )) : <EmptyState text={t("dashboard.noAlertsYet")} />}
          </div>
        </div>
      </section>

      <div className="system-note"><ShieldCheck size={15} /> {t("dashboard.tlsNote")}</div>
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
