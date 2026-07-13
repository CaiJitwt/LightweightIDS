import { useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Network, Search, Server, ShieldAlert } from "lucide-react";

import { hosts } from "../data/mockData";

const protocolColors = ["#2878d0", "#2f8f66", "#8b5cf6", "#d97706"];

export function HostsPage() {
  const [query, setQuery] = useState("");
  const [selectedIp, setSelectedIp] = useState(hosts[0].ip);
  const visible = hosts.filter((host) => `${host.ip} ${host.name} ${host.role}`.toLowerCase().includes(query.toLowerCase()));
  const selected = hosts.find((host) => host.ip === selectedIp) ?? hosts[0];

  return (
    <div className="page-stack">
      <section className="filter-row"><label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search hosts, names or roles" /></label><span className="result-count">{visible.length} observed hosts</span></section>
      <div className="host-workspace">
        <section className="host-list" aria-label="Observed hosts">
          {visible.map((host) => <button type="button" className={host.ip === selected.ip ? "selected-host" : ""} key={host.ip} onClick={() => setSelectedIp(host.ip)}><span className="host-avatar"><Server size={16} /></span><span><strong>{host.name}</strong><small>{host.ip} - {host.role}</small></span><span className={`risk-score risk-${host.risk >= 80 ? "high" : host.risk >= 50 ? "medium" : "low"}`}>{host.risk}</span></button>)}
        </section>
        <section className="host-detail">
          <header className="host-detail-header"><div><span className="eyebrow">Host profile</span><h2>{selected.name}</h2><p>{selected.ip} - {selected.role}</p></div><span className={`risk-score large risk-${selected.risk >= 80 ? "high" : selected.risk >= 50 ? "medium" : "low"}`}>{selected.risk}</span></header>
          <div className="host-metrics"><div><Network size={16} /><span>Packets<strong>{selected.packets.toLocaleString()}</strong></span></div><div><ShieldAlert size={16} /><span>Alerts<strong>{selected.alerts}</strong></span></div><div><Server size={16} /><span>Importance<strong>{selected.importance}</strong></span></div></div>
          <div className="host-analysis">
            <div className="protocol-chart"><h3>Protocol profile</h3><ResponsiveContainer width="100%" height={190}><PieChart><Pie data={selected.protocols} dataKey="value" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} isAnimationActive={false}>{selected.protocols.map((entry, index) => <Cell key={entry.name} fill={protocolColors[index % protocolColors.length]} />)}</Pie><Tooltip /></PieChart></ResponsiveContainer><div className="chart-legend">{selected.protocols.map((entry, index) => <span key={entry.name}><i style={{ background: protocolColors[index % protocolColors.length] }} />{entry.name} {entry.value}%</span>)}</div></div>
            <div className="connection-map"><h3>Recent connections</h3><div className="topology"><span className="topology-host">{selected.ip}</span><i /><span>10.0.0.1<br /><small>Gateway</small></span><i /><span>10.0.0.12<br /><small>SMB</small></span><i /><span>1.1.1.1<br /><small>DNS</small></span></div><div className="connection-events"><p><strong>20:42:18</strong> TLS session to 10.0.0.8:443</p><p><strong>20:41:58</strong> Administrative service access observed</p><p><strong>20:39:14</strong> Host behavior risk score recalculated</p></div></div>
          </div>
        </section>
      </div>
    </div>
  );
}
