import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Cpu, HardDrive, MemoryStick, Network, RefreshCw, Wifi, WifiOff } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { idsApi } from "../api/idsApi";
import type { SystemHealthSnapshot } from "../types";

interface HealthPoint {
  time: string;
  cpu: number;
  memory: number;
  packets: number;
  alerts: number;
}

export function SystemHealthPage({ refreshVersion }: { refreshVersion: number }) {
  const [snapshot, setSnapshot] = useState<SystemHealthSnapshot | null>(null);
  const [history, setHistory] = useState<HealthPoint[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const next = await idsApi.systemHealth();
      setSnapshot(next);
      setError("");
      const memoryPercent = next.system.memoryTotalBytes
        ? next.system.memoryUsedBytes * 100 / next.system.memoryTotalBytes
        : 0;
      setHistory((current) => [...current, {
        time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        cpu: next.system.cpuPercent,
        memory: Math.round(memoryPercent * 10) / 10,
        packets: next.engine.packetsPerSecond,
        alerts: next.engine.sessionAlerts,
      }].slice(-60));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Local system health is unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 5000);
    return () => window.clearInterval(timer);
  }, [load, refreshVersion]);

  const detectors = useMemo(() => snapshot
    ? [...snapshot.detectors].sort((left, right) => Number(right.enabled) - Number(left.enabled) || right.hits - left.hits)
    : [], [snapshot]);
  const memoryPercent = snapshot?.system.memoryTotalBytes
    ? snapshot.system.memoryUsedBytes * 100 / snapshot.system.memoryTotalBytes
    : 0;
  const diskPercent = snapshot?.system.diskTotalBytes
    ? snapshot.system.diskUsedBytes * 100 / snapshot.system.diskTotalBytes
    : 0;

  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <div className="health-status-bar">
        <span className={`health-connection ${snapshot ? "health-online" : error ? "health-offline" : "health-checking"}`}>
          {snapshot ? <Wifi size={14} /> : error ? <WifiOff size={14} /> : <Activity size={14} />}
          {snapshot ? `Local host: ${snapshot.system.hostname}` : error ? "Local health API unavailable" : "Reading local host"}
        </span>
        <span className="health-meta"><strong>API</strong> {snapshot ? `v${snapshot.engine.apiVersion}` : "Unknown"}</span>
        <span className="health-meta"><strong>Uptime</strong> {snapshot ? formatDuration(snapshot.engine.uptimeSeconds) : "Unknown"}</span>
        <button className="icon-button" type="button" title="Refresh local health data" disabled={loading} onClick={() => void load()}><RefreshCw className={loading ? "spin" : ""} size={15} /></button>
      </div>

      {error ? <p className="capture-notice error">{error}. Start this frontend with modern_main.py and stop any older API process using port 8787.</p> : null}

      {snapshot ? <>
        <section className="metric-strip">
          <GaugeMetric icon={<Cpu size={18} />} label="CPU" value={`${snapshot.system.cpuPercent.toFixed(1)}%`} meta={`${snapshot.system.logicalProcessors} logical processors`} color={gaugeColor(snapshot.system.cpuPercent, 70, 90)} />
          <GaugeMetric icon={<MemoryStick size={18} />} label="Memory" value={`${memoryPercent.toFixed(1)}%`} meta={`${formatBytes(snapshot.system.memoryUsedBytes)} of ${formatBytes(snapshot.system.memoryTotalBytes)}`} color={gaugeColor(memoryPercent, 75, 90)} />
          <GaugeMetric icon={<HardDrive size={18} />} label="Disk" value={`${diskPercent.toFixed(1)}%`} meta={`${formatBytes(snapshot.system.diskFreeBytes)} free`} color={gaugeColor(diskPercent, 80, 92)} />
          <GaugeMetric icon={<Network size={18} />} label="Packet rate" value={`${snapshot.engine.packetsPerSecond.toFixed(1)}/s`} meta={`${titleCase(snapshot.engine.captureState)} - ${snapshot.engine.captureInterface}`} color={snapshot.engine.captureState === "running" ? "#2f8f66" : "#2878d0"} />
        </section>

        <section className="analysis-grid">
          <HealthChart title="CPU and memory" meta="Live samples from this browser session" data={history} keys={[{ key: "cpu", name: "CPU %", color: "#2878d0", fill: "#dcecff" }, { key: "memory", name: "Memory %", color: "#d97706", fill: "#feebc8" }]} />
          <HealthChart title="Packet throughput" meta="Current capture session" data={history} keys={[{ key: "packets", name: "Packets/s", color: "#2f8f66", fill: "#d8f3e6" }]} />
        </section>

        <section className="health-details">
          <div className="section-panel">
            <header className="section-heading"><div><h2>Engine diagnostics</h2><p>{snapshot.system.platform}</p></div></header>
            <div className="health-table-wrap">
              <table className="data-table"><tbody>
                <HealthRow label="Detection rules" value={`${snapshot.engine.activeRules} active / ${snapshot.engine.rulesLoaded} loaded`} />
                <HealthRow label="Packets stored" value={snapshot.engine.packetsStored.toLocaleString()} />
                <HealthRow label="Alerts stored" value={snapshot.engine.alertsStored.toLocaleString()} />
                <HealthRow label="Session packets" value={snapshot.engine.sessionPackets.toLocaleString()} />
                <HealthRow label="Session alerts" value={snapshot.engine.sessionAlerts.toLocaleString()} />
                <HealthRow label="Capture state" value={titleCase(snapshot.engine.captureState)} status={snapshot.engine.captureState === "running" ? "ok" : undefined} />
                <HealthRow label="Database size" value={formatBytes(snapshot.engine.databaseBytes)} />
              </tbody></table>
            </div>
          </div>
          <div className="section-panel">
            <header className="section-heading"><div><h2>Active detectors</h2><p>Configured rules and persisted alert hits</p></div></header>
            <div className="detector-list">
              {detectors.slice(0, 14).map((detector) => <div key={detector.id} className="detector-row">
                <span className={`live-dot ${detector.enabled ? "" : "paused"}`} />
                <span className="detector-name"><strong>{detector.name}</strong><small>{detector.enabled ? `Active - ${detector.severity}` : "Disabled"}</small></span>
                <span className="detector-hits">{detector.hits.toLocaleString()} hits</span>
              </div>)}
              {!detectors.length ? <p className="empty-state">No rule records are available.</p> : null}
            </div>
          </div>
        </section>
      </> : !error ? <p className="empty-state">Reading current host and engine status...</p> : null}
    </div>
  );
}

function HealthChart({ title, meta, data, keys }: { title: string; meta: string; data: HealthPoint[]; keys: { key: keyof HealthPoint; name: string; color: string; fill: string }[] }) {
  return <div className="section-panel"><header className="section-heading"><div><h2>{title}</h2><p>{meta}</p></div></header><div className="chart-area">
    {data.length ? <ResponsiveContainer width="100%" height="100%"><AreaChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" /><XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} minTickGap={28} /><YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />{keys.map((item) => <Area key={item.key} type="monotone" dataKey={item.key} stroke={item.color} fill={item.fill} strokeWidth={2} isAnimationActive={false} name={item.name} />)}</AreaChart></ResponsiveContainer> : <p className="empty-state">Waiting for the first local sample.</p>}
  </div></div>;
}

function GaugeMetric({ icon, label, value, meta, color }: { icon: React.ReactNode; label: string; value: string; meta: string; color: string }) {
  return <div className="metric" style={{ borderLeftColor: color }}><div className="metric-icon">{icon}</div><div><span>{label}</span><strong>{value}</strong><small>{meta}</small></div></div>;
}

function HealthRow({ label, value, status }: { label: string; value: string; status?: "ok" }) {
  return <tr><td style={{ color: "var(--muted)" }}>{label}</td><td style={{ textAlign: "right", fontWeight: 600 }}>{value}{status ? <span style={{ marginLeft: 6, color: "#2f8f66" }}>Active</span> : null}</td></tr>;
}

function gaugeColor(value: number, warning: number, critical: number) {
  return value >= critical ? "#c2413b" : value >= warning ? "#d97706" : "#2f8f66";
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[unit]}`;
}

function formatDuration(seconds: number) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

function titleCase(value: string) {
  return value ? `${value[0].toUpperCase()}${value.slice(1)}` : "Unknown";
}
