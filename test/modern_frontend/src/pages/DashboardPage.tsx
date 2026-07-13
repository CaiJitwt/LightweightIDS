import { Activity, BellRing, Radio, ShieldCheck, TriangleAlert } from "lucide-react";
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

import { SeverityBadge } from "../components/SeverityBadge";
import { alerts, hosts, severityDistribution, trendData } from "../data/mockData";

interface DashboardPageProps {
  onOpenAlerts: () => void;
  refreshVersion: number;
}

export function DashboardPage({ onOpenAlerts, refreshVersion }: DashboardPageProps) {
  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <section className="metric-strip" aria-label="Current IDS statistics">
        <Metric icon={<Radio size={18} />} label="Capture status" value="Live" meta="Ethernet 3" tone="green" />
        <Metric icon={<Activity size={18} />} label="Packets today" value="48,291" meta="1,204 in last hour" tone="blue" />
        <Metric icon={<BellRing size={18} />} label="Open alerts" value="29" meta="9 high priority" tone="amber" />
        <Metric icon={<TriangleAlert size={18} />} label="High-risk hosts" value="3" meta="1 newly elevated" tone="red" />
      </section>

      <section className="analysis-grid">
        <div className="section-panel trend-panel">
          <SectionHeading title="Traffic and alert trend" meta="Last 12 hours" />
          <div className="chart-area" aria-label="Traffic and alert trend chart">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" />
                <XAxis dataKey="time" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Area type="monotone" dataKey="packets" stroke="#2878d0" fill="#dcecff" strokeWidth={2} isAnimationActive={false} />
                <Area type="monotone" dataKey="alerts" stroke="#c2413b" fill="#fde2e0" strokeWidth={2} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="section-panel severity-panel">
          <SectionHeading title="Severity distribution" meta="29 alerts" />
          <div className="chart-area" aria-label="Severity distribution chart">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution} layout="vertical" margin={{ top: 8, right: 16, left: 8, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--chart-grid)" />
                <XAxis type="number" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={56} tick={{ fontSize: 11 }} />
                <Tooltip cursor={{ fill: "var(--hover)" }} contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} />
                <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={false}>
                  {severityDistribution.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="dashboard-lower">
        <div className="section-panel host-risk-panel">
          <SectionHeading title="High-risk hosts" meta="Prioritized by composite risk" />
          <div className="compact-list">
            {hosts.slice(0, 4).map((host) => (
              <div className="risk-row" key={host.ip}>
                <div className="host-identity">
                  <span className="host-avatar">{host.name.slice(0, 2).toUpperCase()}</span>
                  <span><strong>{host.name}</strong><small>{host.ip} - {host.role}</small></span>
                </div>
                <span className={`risk-score risk-${host.risk >= 80 ? "high" : host.risk >= 50 ? "medium" : "low"}`}>{host.risk}</span>
                <span className="host-alert-count">{host.alerts} alerts</span>
              </div>
            ))}
          </div>
        </div>

        <div className="section-panel recent-alerts-panel">
          <SectionHeading
            title="Recent alerts"
            meta="Live analyst queue"
            action={<button className="text-button" type="button" onClick={onOpenAlerts}>Open Alert Center</button>}
          />
          <div className="compact-list">
            {alerts.slice(0, 4).map((alert) => (
              <button className="alert-row" type="button" key={alert.id} onClick={onOpenAlerts}>
                <SeverityBadge severity={alert.severity} />
                <span><strong>{alert.ruleName}</strong><small>{alert.source} to {alert.destination}</small></span>
                <time>{alert.timestamp}</time>
              </button>
            ))}
          </div>
        </div>
      </section>

      <div className="system-note"><ShieldCheck size={15} /> HTTPS payload remains encrypted; TLS items show metadata and fingerprint risk only.</div>
    </div>
  );
}

function Metric({ icon, label, value, meta, tone }: { icon: React.ReactNode; label: string; value: string; meta: string; tone: string }) {
  return (
    <div className={`metric metric-${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div><span>{label}</span><strong>{value}</strong><small>{meta}</small></div>
    </div>
  );
}

function SectionHeading({ title, meta, action }: { title: string; meta: string; action?: React.ReactNode }) {
  return <header className="section-heading"><div><h2>{title}</h2><p>{meta}</p></div>{action}</header>;
}
