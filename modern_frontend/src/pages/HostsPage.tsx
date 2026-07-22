import { useEffect, useMemo, useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { ArrowDownLeft, ArrowUpRight, Network, Search, Server, ShieldAlert } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { hosts as previewHosts } from "../data/mockData";
import type { HostProfile, HostRecord } from "../types";
import { useT } from "../i18n/context";

const protocolColors = ["#2878d0", "#2f8f66", "#8b5cf6", "#d97706", "#c2413b"];

interface HostsPageProps {
  initialHostIp?: string;
  refreshVersion: number;
}

export function HostsPage({ initialHostIp, refreshVersion }: HostsPageProps) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [records, setRecords] = useState<HostRecord[]>([]);
  const [selectedIp, setSelectedIp] = useState("");
  const [profile, setProfile] = useState<HostProfile>(() => previewProfile({ ip: "", name: "", role: "", risk: 0, importance: 0, packets: 0, alerts: 0, lastSeen: "" }));
  const [connected, setConnected] = useState(false);
  const [profileFallback, setProfileFallback] = useState(false);

  useEffect(() => {
    let active = true;
    idsApi.hosts()
      .then(({ records: next }) => {
        if (!active) return;
        setRecords(next);
        setConnected(true);
        setSelectedIp((current) => next.some((host) => host.ip === current) ? current : next[0]?.ip ?? "");
      })
      .catch(() => {
        if (active) setConnected(false);
      });
    return () => { active = false; };
  }, [refreshVersion]);

  useEffect(() => {
    if (!initialHostIp || !records.some((host) => host.ip === initialHostIp)) return;
    setSelectedIp(initialHostIp);
  }, [initialHostIp, records]);

  useEffect(() => {
    const fallback = records.find((host) => host.ip === selectedIp) ?? records[0];
    if (!fallback) return;
    let active = true;
    setProfileFallback(false);
    idsApi.host(selectedIp)
      .then((next) => { if (active) setProfile(next); })
      .catch(() => { if (active) { setProfile(previewProfile(fallback)); setProfileFallback(true); } });
    return () => { active = false; };
  }, [records, selectedIp]);

  const visible = useMemo(() => records.filter((host) => `${host.ip} ${host.name} ${host.role}`.toLowerCase().includes(query.toLowerCase())), [query, records]);
  const selected = profile.host;
  const protocols = profile.protocols.length ? profile.protocols : selected.protocols ?? [];

  return (
    <div className="page-stack">
      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("hosts.search")} /></label>
        <span className="result-count">{t("hosts.observed", { count: visible.length })} - {connected ? t("dashboard.localData") : t("alerts.offlinePreview")}</span>
      </section>
      <div className="host-workspace">
        <section className="host-list" aria-label="Observed hosts">
          {visible.length ? visible.map((host) => <button type="button" className={host.ip === selected.ip ? "selected-host" : ""} key={host.ip} onClick={() => setSelectedIp(host.ip)}><span className="host-avatar"><Server size={16} /></span><span><strong>{host.name}</strong><small>{host.ip} - {host.role}</small></span><span className={`risk-score risk-${host.risk >= 80 ? "high" : host.risk >= 50 ? "medium" : "low"}`}>{host.risk}</span></button>) : <p className="empty-state">{t("hosts.noHosts")}</p>}
        </section>
        <section className="host-detail" aria-label="Host profile details">
          <header className="host-detail-header"><div><span className="eyebrow">{t("hosts.profile")}{profileFallback && ` · ${t("hosts.previewLabel")}`}</span><h2>{selected.name}</h2><p>{selected.ip} - {selected.role}</p></div><span className={`risk-score large risk-${selected.risk >= 80 ? "high" : selected.risk >= 50 ? "medium" : "low"}`}>{selected.risk}</span></header>
          <div className="host-metrics"><Metric icon={<Network size={16} />} label={t("hosts.packets")} value={selected.packets.toLocaleString()} /><Metric icon={<ArrowUpRight size={16} />} label={t("hosts.outbound")} value={(selected.outgoingPackets ?? 0).toLocaleString()} /><Metric icon={<ArrowDownLeft size={16} />} label={t("hosts.inbound")} value={(selected.incomingPackets ?? 0).toLocaleString()} /><Metric icon={<ShieldAlert size={16} />} label={t("hosts.alerts")} value={selected.alerts.toString()} /></div>
          <div className="host-analysis">
            <div className="protocol-chart"><h3>{t("hosts.protocolProfile")}</h3>{protocols.length ? <><ResponsiveContainer width="100%" height={190}><PieChart><Pie data={protocols} dataKey="value" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} isAnimationActive={false}>{protocols.map((entry, index) => <Cell key={entry.name} fill={protocolColors[index % protocolColors.length]} />)}</Pie><Tooltip /></PieChart></ResponsiveContainer><div className="chart-legend">{protocols.map((entry, index) => <span key={entry.name}><i style={{ background: protocolColors[index % protocolColors.length] }} />{entry.name} {entry.value}</span>)}</div></> : <p className="empty-state">{t("hosts.noProtocolProfile")}</p>}</div>
            <div className="connection-map"><h3>{t("hosts.recentConnections")}</h3>{profile.connections.length > 0 && <div className="topology"><span className="topology-host">{selected.ip}<br /><small>{selected.role}</small></span>{profile.connections.slice(0, 3).map((connection) => <div className="topology-peer" key={`${connection.peer}-${connection.protocol}-${connection.port}`}><i /><span>{connection.peer}<br /><small>{connection.protocol}{connection.port ? `:${connection.port}` : ""}</small></span></div>)}</div>}<div className="connection-events">{profile.timeline.slice(0, 4).map((event, index) => <p key={`${event.timestamp}-${index}`}><strong>{event.timestamp}</strong>{event.type === "Alert" ? "Alert" : event.direction}: {event.summary}</p>)}{!profile.timeline.length && <p>{t("hosts.noActivity")}</p>}</div></div>
          </div>
          <section className="host-reasons"><h3>{t("hosts.riskSignals")}</h3>{selected.riskReasons?.length ? <ul>{selected.riskReasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : <p>{t("hosts.noRiskSignals")}</p>}</section>
        </section>
      </div>
    </div>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return <div>{icon}<span>{label}<strong>{value}</strong></span></div>;
}

function previewProfile(host: HostRecord): HostProfile {
  return { host, protocols: host.protocols ?? [], ports: [], connections: [], alerts: [], timeline: [] };
}
