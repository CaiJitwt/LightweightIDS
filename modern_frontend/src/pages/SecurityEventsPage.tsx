import { useCallback, useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { BellRing, Database, Play, RefreshCw, Search, ShieldAlert, Square, Waypoints } from "lucide-react";

import { idsApi } from "../api/idsApi";
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
    { accessorKey: "eventId", header: "Event ID" },
    { accessorKey: "channel", header: "Channel", cell: ({ getValue }) => <span className="event-channel" title={String(getValue())}>{shortChannel(String(getValue()))}</span> },
    { accessorKey: "user", header: "User", cell: ({ getValue }) => String(getValue() || "-") },
    { accessorKey: "sourceIp", header: "Source", cell: ({ getValue }) => String(getValue() || "Local") },
    { accessorKey: "summary", header: "Summary", enableSorting: false },
  ], []);

  const runAction = async (action: "start" | "stop" | "refresh") => {
    setBusy(true);
    try {
      const next = action === "start" ? await idsApi.startSecurityEvents() : action === "stop" ? await idsApi.stopSecurityEvents() : await idsApi.refreshSecurityEvents();
      setStatus(next);
      setConnected(true);
      await load();
    } catch (error) {
      setStatus((current) => ({ ...current, lastError: error instanceof Error ? error.message : "Security event action failed." }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page-stack security-events-page">
      <section className="security-event-toolbar">
        <div className="security-event-state"><span className={`live-dot ${status.state === "running" ? "" : "paused"}`} /><div><strong>{status.state === "running" ? "Monitoring Windows events" : "Windows event monitor stopped"}</strong><small>{connected ? `${status.pollSeconds}s polling interval` : "Local API unavailable"}</small></div></div>
        <div className="security-event-actions">
          {status.state === "running" ? <button className="icon-text-button" type="button" disabled={busy} onClick={() => void runAction("stop")}><Square size={14} />Stop</button> : <button className="icon-text-button primary-action" type="button" disabled={busy || !status.platformAvailable} onClick={() => void runAction("start")}><Play size={14} />Start monitoring</button>}
          <button className="icon-button" type="button" title="Collect security events now" disabled={busy || !status.platformAvailable} onClick={() => void runAction("refresh")}><RefreshCw size={15} /></button>
        </div>
      </section>

      <section className="metric-strip">
        <Metric icon={<Database size={18} />} label="Persisted events" value={status.eventTotal} meta={`${status.sessionEvents} this session`} tone="blue" />
        <Metric icon={<ShieldAlert size={18} />} label="High-risk events" value={highRisk} meta="Critical and high severity" tone="red" />
        <Metric icon={<BellRing size={18} />} label="Generated alerts" value={status.sessionAlerts} meta="Current monitor session" tone="amber" />
        <Metric icon={<Waypoints size={18} />} label="Available channels" value={availableChannels} meta={`${status.unavailableChannels.length} unavailable`} tone="green" />
      </section>

      <section className="filter-row security-event-filters">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search users, hosts, processes or summaries" /></label>
        <select className="plain-select" aria-label="Security event severity" value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <select className="plain-select event-channel-select" aria-label="Security event channel" value={channel} onChange={(event) => setChannel(event.target.value)}><option>All channels</option>{channels.map((value) => <option key={value}>{value}</option>)}</select>
        <input className="table-input event-id-filter" aria-label="Windows Event ID" value={eventId} onChange={(event) => setEventId(event.target.value.replace(/\D/g, ""))} placeholder="Event ID" />
        <span className="result-count">{records.length} events</span>
      </section>

      {status.lastError && <p className="capture-notice error">{status.lastError}</p>}

      <div className="master-detail security-event-workspace">
        <section className="table-panel security-event-table"><DataTable columns={columns} data={records} getRowId={(row) => String(row.id)} selectedRowId={selected ? String(selected.id) : undefined} onRowClick={(row) => setSelectedId(row.id)} /></section>
        <aside className="detail-panel security-event-detail" aria-label="Selected Windows security event">
          {selected ? <>
            <header className="detail-header"><div><SeverityBadge severity={selected.severity} /><h2>Windows Event {selected.eventId}</h2><p>Record #{selected.recordId} - {selected.timestamp}</p></div></header>
            <dl className="detail-grid"><Detail label="Channel" value={selected.channel} /><Detail label="Computer" value={selected.computer} /><Detail label="User" value={selected.user || "Unknown"} /><Detail label="Source IP" value={selected.sourceIp || "Local or unavailable"} /><Detail label="Logon type" value={selected.logonType || "-"} /><Detail label="Provider" value={selected.provider} /></dl>
            <div className="detail-section"><h3>Event summary</h3><p>{selected.summary}</p></div>
            {(selected.processName || selected.commandLine) && <div className="detail-section"><h3>Execution context</h3>{selected.processName && <p>{selected.processName}</p>}{selected.commandLine && <code>{selected.commandLine}</code>}</div>}
            <div className="detail-section"><h3>Structured event data</h3><code>{JSON.stringify(selected.details, null, 2)}</code></div>
            {selected.alertId && <footer className="detail-actions single-action"><button type="button" onClick={() => onOpenAlert(selected.alertId!)}><BellRing size={15} />Open related alert</button></footer>}
          </> : <div className="empty-detail">Select a Windows security event to inspect its normalized fields.</div>}
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
