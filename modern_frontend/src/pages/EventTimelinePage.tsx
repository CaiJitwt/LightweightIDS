import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, BellRing, Clock, Filter, Network, Radio, Search } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import type { EventTimelineRecord } from "../types";


const kindColors: Record<EventTimelineRecord["kind"], string> = { alert: "#c2413b", packet: "#2878d0", system: "#6d7f90" };
const kindLabels: Record<EventTimelineRecord["kind"], string> = { alert: "Alert", packet: "Packet", system: "System" };


export function EventTimelinePage({ refreshVersion }: { refreshVersion: number }) {
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("All");
  const [sortAsc, setSortAsc] = useState(false);
  const [records, setRecords] = useState<EventTimelineRecord[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    idsApi.timeline().then(({ records: next }) => {
      if (active) {
        setRecords(next);
        setError("");
      }
    }).catch((reason) => {
      if (active) {
        setRecords([]);
        setError(reason instanceof Error ? reason.message : "Persisted timeline data is unavailable.");
      }
    });
    return () => { active = false; };
  }, [refreshVersion]);

  const visible = useMemo(() => {
    let list = records;
    if (kindFilter !== "All") list = list.filter((entry) => entry.kind === kindFilter.toLowerCase());
    if (query.trim()) {
      const normalized = query.toLowerCase();
      list = list.filter((entry) => `${entry.headline} ${entry.detail} ${entry.source} ${entry.destination ?? ""}`.toLowerCase().includes(normalized));
    }
    return sortAsc ? [...list].reverse() : list;
  }, [records, query, kindFilter, sortAsc]);

  const alertCount = records.filter((entry) => entry.kind === "alert").length;
  const packetCount = records.filter((entry) => entry.kind === "packet").length;
  const systemCount = records.filter((entry) => entry.kind === "system").length;

  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <section className="timeline-summary">
        <TimelineMetric icon={<BellRing size={15} />} label="Alerts" value={alertCount} color="#c2413b" background="#fde2e0" />
        <TimelineMetric icon={<Network size={15} />} label="Packets" value={packetCount} color="#2878d0" background="#dcecff" />
        <TimelineMetric icon={<Radio size={15} />} label="System events" value={systemCount} color="#6d7f90" background="#e5eaee" />
      </section>

      {error && <p className="capture-notice error">{error}</p>}

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search timeline events" /></label>
        <label className="select-box"><Filter size={15} />
          <select aria-label="Timeline event type" value={kindFilter} onChange={(event) => setKindFilter(event.target.value)}>
            <option>All</option><option>Alert</option><option>Packet</option><option>System</option>
          </select>
        </label>
        <button className="icon-button" type="button" title={sortAsc ? "Switch to newest first" : "Switch to oldest first"} onClick={() => setSortAsc((value) => !value)}>
          {sortAsc ? <ArrowUp size={17} /> : <ArrowDown size={17} />}
        </button>
        <span className="result-count">{visible.length} events</span>
      </section>

      <section className="section-panel">
        <div className="timeline" style={{ padding: "2px 14px" }}>
          {!visible.length ? <p className="empty-hint" style={{ padding: 32, textAlign: "center" }}>No persisted timeline events match the current filters.</p> : visible.map((entry, index) => {
            const isLast = index === visible.length - 1;
            const color = kindColors[entry.kind];
            return <div key={entry.id} className={`timeline-entry ${isLast ? "timeline-entry-last" : ""}`}>
              <div className="timeline-marker"><span className="timeline-dot" style={{ background: color, boxShadow: `0 0 0 3px ${color}22` }} />{!isLast && <span className="timeline-line" />}</div>
              <div className="timeline-card">
                <div className="timeline-card-header">
                  <div className="timeline-card-kind"><span className={`protocol protocol-${entry.kind === "alert" ? "dns" : entry.kind === "packet" ? "tls" : "tcp"}`}>{kindLabels[entry.kind]}</span>{entry.severity && <SeverityBadge severity={entry.severity} />}</div>
                  <time className="timeline-time"><Clock size={11} />{entry.timestamp}</time>
                </div>
                <strong className="timeline-headline">{entry.headline}</strong>
                <p className="timeline-detail">{entry.detail}</p>
                <div className="timeline-card-footer"><span>{entry.source}</span>{entry.destination && <span className="timeline-arrow">-&gt; {entry.destination}</span>}</div>
              </div>
            </div>;
          })}
        </div>
      </section>
    </div>
  );
}


function TimelineMetric({ icon, label, value, color, background }: { icon: React.ReactNode; label: string; value: number; color: string; background: string }) {
  return <div className="timeline-stat" style={{ borderLeftColor: color }}><div className="stat-icon" style={{ color, background }}>{icon}</div><div><span>{label}</span><strong>{value}</strong></div></div>;
}
