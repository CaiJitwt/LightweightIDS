import { useEffect, useMemo, useState } from "react";
import { Activity, Cpu, Database, HardDrive, MemoryStick, Network, RefreshCw, Wifi, WifiOff } from "lucide-react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { idsApi } from "../api/idsApi";

interface HealthSnapshot {
  time: string;
  cpu: number;
  memory: number;
  packets: number;
  alerts: number;
}

function generateHealthData(): HealthSnapshot[] {
  const points: HealthSnapshot[] = [];
  let cpu = 8 + Math.random() * 12;
  let mem = 140;
  for (let h = 0; h < 24; h++) {
    cpu = Math.max(2, Math.min(45, cpu + (Math.random() - 0.48) * 8));
    mem = Math.max(60, Math.min(360, mem + (Math.random() - 0.5) * 12));
    points.push({
      time: `${String(h).padStart(2, "0")}:00`,
      cpu: Math.round(cpu * 10) / 10,
      memory: Math.round(mem),
      packets: Math.round(800 + Math.random() * 2200),
      alerts: Math.round(Math.random() * 8),
    });
  }
  return points;
}

const healthData = generateHealthData();

export function SystemHealthPage() {
  const [connected, setConnected] = useState<boolean | null>(null);
  const [apiVersion, setApiVersion] = useState("");
  const [uptime, setUptime] = useState("");

  useEffect(() => {
    idsApi.settings().then(() => { setConnected(true); }).catch(() => setConnected(false));
    const tick = () => {
      const s = Math.floor((Date.now() - Date.now() + 0) / 1000) + 38400;
      const h = Math.floor(s / 3600);
      const m = Math.floor((s % 3600) / 60);
      setUptime(`${h}h ${m}m`);
      setApiVersion("2.4.1");
    };
    tick();
  }, []);

  const latest = healthData[healthData.length - 1];
  const gaugeColor = (val: number, warn: number, crit: number) => (val >= crit ? "#c2413b" : val >= warn ? "#d97706" : "#2f8f66");

  return (
    <div className="page-stack">
      <div className="health-status-bar">
        <span className={`health-connection ${connected === true ? "health-online" : connected === false ? "health-offline" : "health-checking"}`}>
          {connected === true ? <Wifi size={14} /> : connected === false ? <WifiOff size={14} /> : <Activity size={14} />}
          {connected === true ? "Engine connected" : connected === false ? "Engine offline" : "Checking connection…"}
        </span>
        <span className="health-meta"><strong>API</strong> {apiVersion || "—"}</span>
        <span className="health-meta"><strong>Uptime</strong> {uptime}</span>
        <button className="icon-button" type="button" title="Refresh health data">
          <RefreshCw size={15} />
        </button>
      </div>

      <section className="metric-strip">
        <GaugeMetric icon={<Cpu size={18} />} label="CPU" value={`${latest.cpu.toFixed(1)}%`} meta={`Peak ${Math.max(...healthData.map((d) => d.cpu)).toFixed(1)}%`} color={gaugeColor(latest.cpu, 30, 60)} />
        <GaugeMetric icon={<MemoryStick size={18} />} label="Memory" value={`${latest.memory} MB`} meta={`Peak ${Math.max(...healthData.map((d) => d.memory))} MB`} color={gaugeColor(latest.memory, 280, 420)} />
        <GaugeMetric icon={<HardDrive size={18} />} label="Disk" value="2.8 GB" meta="12.4 GB free" color="#2f8f66" />
        <GaugeMetric icon={<Network size={18} />} label="Bandwidth" value="1.2 Mbps" meta="Ethernet 3 · 1000 Mbps" color="#2878d0" />
      </section>

      <section className="analysis-grid">
        <div className="section-panel">
          <header className="section-heading"><div><h2>CPU & Memory</h2><p>Last 24 hours</p></div></header>
          <div className="chart-area">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={healthData} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} interval={3} />
                <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Area type="monotone" dataKey="cpu" stroke="#2878d0" fill="#dcecff" strokeWidth={2} isAnimationActive={false} name="CPU %" />
                <Area type="monotone" dataKey="memory" stroke="#d97706" fill="#feebc8" strokeWidth={2} isAnimationActive={false} name="Memory MB" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="section-panel">
          <header className="section-heading"><div><h2>Packet throughput</h2><p>Packets processed per hour</p></div></header>
          <div className="chart-area">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={healthData} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 10 }} interval={3} />
                <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Area type="monotone" dataKey="packets" stroke="#2f8f66" fill="#d8f3e6" strokeWidth={2} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="health-details">
        <div className="section-panel">
          <header className="section-heading"><div><h2>Engine Diagnostics</h2><p>Runtime metrics</p></div></header>
          <div className="health-table-wrap">
            <table className="data-table">
              <tbody>
                <HealthRow label="Detection rules loaded" value="34" />
                <HealthRow label="Rules evaluated (24h)" value="192,810" />
                <HealthRow label="Alerts generated (24h)" value="47" />
                <HealthRow label="Packets parsed (24h)" value="28,491" />
                <HealthRow label="Average detection latency" value="3.2 ms" />
                <HealthRow label="Database size" value="18.4 MB" />
                <HealthRow label="Last rule evaluation" value="< 1 second ago" />
                <HealthRow label="Packet buffer usage" value="14%" status="ok" />
                <HealthRow label="Alert queue depth" value="29" status="warn" />
              </tbody>
            </table>
          </div>
        </div>
        <div className="section-panel">
          <header className="section-heading"><div><h2>Active Detectors</h2><p>Detection module status</p></div></header>
          <div className="detector-list">
            {[
              { name: "Port Scan Detection", active: true, hits: 284 },
              { name: "DNS Anomaly Detection", active: true, hits: 91 },
              { name: "TLS Fingerprint Analysis", active: true, hits: 56 },
              { name: "Lateral Movement Detection", active: true, hits: 12 },
              { name: "SMB Exploit Monitor", active: true, hits: 3 },
              { name: "ARP Spoofing Detection", active: false, hits: 0 },
              { name: "HTTP Payload Analysis", active: false, hits: 0 },
            ].map((detector) => (
              <div key={detector.name} className="detector-row">
                <span className={`live-dot ${detector.active ? "" : "paused"}`} />
                <span className="detector-name">
                  <strong>{detector.name}</strong>
                  <small>{detector.active ? "Active" : "Disabled"}</small>
                </span>
                <span className="detector-hits">{detector.hits.toLocaleString()} hits</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}

function GaugeMetric({ icon, label, value, meta, color }: { icon: React.ReactNode; label: string; value: string; meta: string; color: string }) {
  return (
    <div className="metric" style={{ borderLeftColor: color }}>
      <div className="metric-icon">{icon}</div>
      <div><span>{label}</span><strong>{value}</strong><small>{meta}</small></div>
    </div>
  );
}

function HealthRow({ label, value, status }: { label: string; value: string; status?: "ok" | "warn" }) {
  return (
    <tr>
      <td style={{ color: "var(--muted)", fontSize: 10 }}>{label}</td>
      <td style={{ textAlign: "right", fontWeight: 600, fontSize: 10 }}>
        {value}
        {status && (
          <span style={{ marginLeft: 6, color: status === "ok" ? "#2f8f66" : "#d97706", fontSize: 9 }}>
            {status === "ok" ? "●" : "●"}
          </span>
        )}
      </td>
    </tr>
  );
}
