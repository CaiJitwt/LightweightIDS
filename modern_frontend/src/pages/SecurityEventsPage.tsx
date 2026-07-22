import { useCallback, useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { BellRing, Database, Play, RefreshCw, Search, ShieldAlert, Square, Waypoints } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import { DataTable } from "../components/DataTable";
import { SeverityBadge } from "../components/SeverityBadge";
import type { SecurityEventRecord, SecurityEventStatus } from "../types";

const stoppedStatus: SecurityEventStatus = {
  state: "stopped",
  platformAvailable: true,
  pollSeconds: 5,
  lastPoll: "",
  lastError: "",
  monitoredChannels: [],
  unavailableChannels: [],
  eventTotal: 0,
  severityCounts: {},
  sessionEvents: 0,
  sessionAlerts: 0,
};

export function SecurityEventsPage({ onOpenAlert }: { onOpenAlert: (alertId: number) => void }) {
  const t = useT();
  const [records, setRecords] = useState<SecurityEventRecord[]>([]);
  const [status, setStatus] = useState<SecurityEventStatus>(stoppedStatus);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [channel, setChannel] = useState("All channels");
  const [eventId, setEventId] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await idsApi.securityEvents({ query, severity, channel, eventId, limit: 500 });
      setRecords(result.records);
      setStatus(result.status);
      setConnected(true);
      setSelectedId((current) => result.records.some((event) => event.id === current) ? current : result.records[0]?.id ?? null);
    } catch {
      setConnected(false);
    }
  }, [channel, eventId, query, severity]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), query ? 180 : 0);
    return () => window.clearTimeout(timer);
  }, [load, query]);

  useEffect(() => {
    if (status.state !== "running") return undefined;
    const timer = window.setInterval(() => void load(), Math.max(2, status.pollSeconds) * 1000);
    return () => window.clearInterval(timer);
  }, [load, status.pollSeconds, status.state]);

  const selected = records.find((event) => event.id === selectedId) ?? null;
  const channels = useMemo(() => {
    const values = new Set([...status.monitoredChannels, ...records.map((event) => event.channel)]);
    return [...values].sort();
  }, [records, status.monitoredChannels]);
  const highRisk = (status.severityCounts.CRITICAL ?? 0) + (status.severityCounts.HIGH ?? 0);
  const availableChannels = Math.max(0, status.monitoredChannels.length - status.unavailableChannels.length);

  const columns = useMemo<ColumnDef<SecurityEventRecord, unknown>[]>(() => [
    { accessorKey: "timestamp", header: "Time" },
    { accessorKey: "severity", header: "Severity", cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { accessorKey: "eventId", header: t("securityEvents.eventIdPlaceholder") },
    { accessorKey: "channel", header: t("securityEvents.channel"), cell: ({ getValue }) => <span className="event-channel" title={String(getValue())}>{shortChannel(String(getValue()))}</span> },
    { accessorKey: "user", header: t("securityEvents.user"), cell: ({ getValue }) => String(getValue() || "-") },
    { accessorKey: "sourceIp", header: "Source", cell: ({ getValue }) => String(getValue() || t("common.local")) },
    { accessorKey: "summary", header: "Summary", enableSorting: false },
  ], [t]);

  const runAction = async (action: "start" | "stop" | "refresh") => {
    setBusy(true);
    try {
      const next = action === "start" ? await idsApi.startSecurityEvents() : action === "stop" ? await idsApi.stopSecurityEvents() : await idsApi.refreshSecurityEvents();
      setStatus(next);
      setConnected(true);
      await load();
    } catch (error) {
      setStatus((current) => ({ ...current, lastError: error instanceof Error ? error.message : t("securityEvents.actionFailed") }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page-stack security-events-page">
      <section className="security-event-toolbar">
        <div className="security-event-state"><span className={`live-dot ${status.state === "running" ? "" : "paused"}`} /><div><strong>{status.state === "running" ? t("securityEvents.monitoring") : t("securityEvents.stopped")}</strong><small>{connected ? t("securityEvents.pollInterval", { seconds: status.pollSeconds }) : t("securityEvents.unavailable")}</small></div></div>
        <div className="security-event-actions">
          {status.state === "running" ? <button className="icon-text-button" type="button" disabled={busy} onClick={() => void runAction("stop")}><Square size={14} />{t("securityEvents.stop")}</button> : <button className="icon-text-button primary-action" type="button" disabled={busy || !status.platformAvailable} onClick={() => void runAction("start")}><Play size={14} />{t("securityEvents.startMonitoring")}</button>}
          <button className="icon-button" type="button" title={t("securityEvents.collectNow")} disabled={busy || !status.platformAvailable} onClick={() => void runAction("refresh")}><RefreshCw size={15} /></button>
        </div>
      </section>

      <section className="metric-strip">
        <Metric icon={<Database size={18} />} label={t("securityEvents.persistedEvents")} value={status.eventTotal} meta={t("securityEvents.thisSession", { count: status.sessionEvents })} tone="blue" />
        <Metric icon={<ShieldAlert size={18} />} label={t("securityEvents.highRiskEvents")} value={highRisk} meta={t("securityEvents.highRiskMeta")} tone="red" />
        <Metric icon={<BellRing size={18} />} label={t("securityEvents.generatedAlerts")} value={status.sessionAlerts} meta={t("securityEvents.generatedMeta")} tone="amber" />
        <Metric icon={<Waypoints size={18} />} label={t("securityEvents.availableChannels")} value={availableChannels} meta={t("securityEvents.channelsMeta", { count: status.unavailableChannels.length })} tone="green" />
      </section>

      <section className="filter-row security-event-filters">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("securityEvents.search")} /></label>
        <select className="plain-select" aria-label="Security event severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option>{t("common.allSeverities")}</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <select className="plain-select event-channel-select" aria-label="Security event channel" value={channel} onChange={(event) => setChannel(event.target.value)}><option>{t("common.allChannels")}</option>{channels.map((value) => <option key={value}>{value}</option>)}</select>
        <input className="table-input event-id-filter" aria-label="Windows Event ID" value={eventId} onChange={(event) => setEventId(event.target.value.replace(/\D/g, ""))} placeholder={t("securityEvents.eventIdPlaceholder")} />
        <span className="result-count">{t("securityEvents.events", { count: records.length })}</span>
      </section>

      {status.lastError && <p className="capture-notice error">{status.lastError}</p>}

      <div className="master-detail security-event-workspace">
        <section className="table-panel security-event-table"><DataTable columns={columns} data={records} getRowId={(row) => String(row.id)} selectedRowId={selected ? String(selected.id) : undefined} onRowClick={(row) => setSelectedId(row.id)} /></section>
        <aside className="detail-panel security-event-detail" aria-label="Selected Windows security event">
          {selected ? <>
            <header className="detail-header"><div><SeverityBadge severity={selected.severity} /><h2>Windows Event {selected.eventId}</h2><p>Record #{selected.recordId} - {selected.timestamp}</p></div></header>
            <dl className="detail-grid"><Detail label={t("securityEvents.channel")} value={selected.channel} /><Detail label={t("securityEvents.computer")} value={selected.computer} /><Detail label={t("securityEvents.user")} value={selected.user || t("common.unknown")} /><Detail label={t("securityEvents.sourceIp")} value={selected.sourceIp || t("securityEvents.localOrUnavailable")} /><Detail label={t("securityEvents.logonType")} value={selected.logonType || "-"} /><Detail label={t("securityEvents.provider")} value={selected.provider} /></dl>
            <div className="detail-section"><h3>{t("securityEvents.eventSummary")}</h3><p>{selected.summary}</p></div>
            {(selected.processName || selected.commandLine) && <div className="detail-section"><h3>{t("securityEvents.executionContext")}</h3>{selected.processName && <p>{selected.processName}</p>}{selected.commandLine && <code>{selected.commandLine}</code>}</div>}
            <div className="detail-section"><h3>{t("securityEvents.structuredData")}</h3><code>{JSON.stringify(selected.details, null, 2)}</code></div>
            {selected.alertId && <footer className="detail-actions single-action"><button type="button" onClick={() => onOpenAlert(selected.alertId!)}><BellRing size={15} />{t("securityEvents.openAlert")}</button></footer>}
          </> : <div className="empty-detail">{t("securityEvents.selectEvent")}</div>}
        </aside>
      </div>
    </div>
  );
}

function Metric({ icon, label, value, meta, tone }: { icon: React.ReactNode; label: string; value: number; meta: string; tone: string }) {
  return <div className={`metric metric-${tone}`}><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{meta}</small></div></div>;
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd title={value}>{value || "-"}</dd></div>;
}

function shortChannel(value: string): string {
  return value.replace("Microsoft-Windows-", "").replace("/Operational", "");
}
