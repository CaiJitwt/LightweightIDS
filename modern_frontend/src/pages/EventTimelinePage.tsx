import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, BellRing, Clock, Filter, Network, Radio, Search } from "lucide-react";
import { SeverityBadge } from "../components/SeverityBadge";
import { alerts, packets } from "../data/mockData";
import type { Severity } from "../types";

type TimelineEntry = {
  id: string;
  utc: number;
  timestamp: string;
  kind: "alert" | "packet" | "system";
  severity?: Severity;
  headline: string;
  detail: string;
  source: string;
  destination?: string;
};

function buildTimeline(): TimelineEntry[] {
  const entries: TimelineEntry[] = [];

  alerts.forEach((a) => {
    entries.push({
      id: `alert-${a.id}`, utc: parseTimestamp(a.timestamp), timestamp: a.timestamp,
      kind: "alert", severity: a.severity, headline: a.ruleName, detail: a.description, source: a.source, destination: a.destination,
    });
  });

  packets.forEach((p) => {
    entries.push({
      id: `pkt-${p.id}`, utc: parseTimestamp(p.timestamp), timestamp: p.timestamp,
      kind: "packet",
      headline: `${p.protocol} ${p.summary.length > 60 ? p.summary.slice(0, 60) + "…" : p.summary}`,
      detail: `${p.source} → ${p.destination} · ${p.length} bytes${p.flags ? ` · Flags: ${p.flags}` : ""}`,
      source: p.source, destination: p.destination,
    });
  });

  entries.push(
    { id: "sys-0", utc: parseTimestamp("20:45:00"), timestamp: "20:45:00", kind: "system", headline: "Detection engine snapshot", detail: "Rule evaluation cycle completed. 3 rules matched.", source: "engine" },
    { id: "sys-1", utc: parseTimestamp("20:30:00"), timestamp: "20:30:00", kind: "system", headline: "Import session started", detail: "Parsed 2,401 packets from the active capture session.", source: "engine" },
    { id: "sys-2", utc: parseTimestamp("20:15:00"), timestamp: "20:15:00", kind: "system", headline: "Capture interface changed", detail: "Active interface switched to Ethernet 3.", source: "engine" },
  );

  entries.sort((a, b) => b.utc - a.utc);
  return entries;
}

function parseTimestamp(ts: string): number {
  const parts = ts.split(":");
  if (parts.length >= 2) {
    const h = Number(parts[0]), m = Number(parts[1]);
    const s = parts.length >= 3 ? Number(parts[2].split(".")[0]) : 0;
    const ms = parts.length >= 3 && parts[2].includes(".") ? Number(`0.${parts[2].split(".")[1]}`) : 0;
    return h * 3600 + m * 60 + s + ms;
  }
  return 0;
}

const kindColors: Record<TimelineEntry["kind"], string> = { alert: "#c2413b", packet: "#2878d0", system: "#6d7f90" };
const kindLabels: Record<TimelineEntry["kind"], string> = { alert: "Alert", packet: "Packet", system: "System" };

export function EventTimelinePage() {
  const [query, setQuery] = useState("");
  const [kindFilter, setKindFilter] = useState("All");
  const [sortAsc, setSortAsc] = useState(false);

  const fullTimeline = useMemo(buildTimeline, []);

  const visible = useMemo(() => {
    let list = fullTimeline;
    if (kindFilter !== "All") list = list.filter((e) => e.kind === kindFilter.toLowerCase());
    if (query.trim()) {
      const q = query.toLowerCase();
      list = list.filter((e) => e.headline.toLowerCase().includes(q) || e.detail.toLowerCase().includes(q) || e.source.toLowerCase().includes(q));
    }
    if (sortAsc) list = [...list].reverse();
    return list;
  }, [fullTimeline, query, kindFilter, sortAsc]);

  const alertCount = fullTimeline.filter((e) => e.kind === "alert").length;
  const packetCount = fullTimeline.filter((e) => e.kind === "packet").length;
  const systemCount = fullTimeline.filter((e) => e.kind === "system").length;

  return (
    <div className="page-stack">
      <section className="timeline-summary">
        <div className="timeline-stat" style={{ borderLeftColor: "#c2413b" }}>
          <div className="stat-icon" style={{ color: "#c2413b", background: "#fde2e0" }}><BellRing size={15} /></div>
          <div><span>Alerts</span><strong>{alertCount}</strong></div>
        </div>
        <div className="timeline-stat" style={{ borderLeftColor: "#2878d0" }}>
          <div className="stat-icon" style={{ color: "#2878d0", background: "#dcecff" }}><Network size={15} /></div>
          <div><span>Packets</span><strong>{packetCount}</strong></div>
        </div>
        <div className="timeline-stat" style={{ borderLeftColor: "#6d7f90" }}>
          <div className="stat-icon" style={{ color: "#6d7f90", background: "#e5eaee" }}><Radio size={15} /></div>
          <div><span>System Events</span><strong>{systemCount}</strong></div>
        </div>
      </section>

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search timeline events…" /></label>
        <label className="select-box"><Filter size={15} />
          <select value={kindFilter} onChange={(e) => setKindFilter(e.target.value)}>
            <option>All</option><option>Alert</option><option>Packet</option><option>System</option>
          </select>
        </label>
        <button className="icon-button" type="button" title={sortAsc ? "Switch to newest first" : "Switch to oldest first"} onClick={() => setSortAsc((v) => !v)}>
          {sortAsc ? <ArrowUp size={17} /> : <ArrowDown size={17} />}
        </button>
        <span className="result-count">{visible.length} events</span>
      </section>

      <section className="section-panel">
        <div className="timeline" style={{ padding: "2px 14px" }}>
          {visible.length === 0 ? (
            <p className="empty-hint" style={{ padding: 32, textAlign: "center" }}>No timeline events match the current filters.</p>
          ) : (
            visible.map((entry, index) => {
              const isLast = index === visible.length - 1;
              const color = kindColors[entry.kind];
              return (
                <div key={entry.id} className={`timeline-entry ${isLast ? "timeline-entry-last" : ""}`}>
                  <div className="timeline-marker">
                    <span className="timeline-dot" style={{ background: color, boxShadow: `0 0 0 3px ${color}22` }} />
                    {!isLast && <span className="timeline-line" />}
                  </div>
                  <div className="timeline-card">
                    <div className="timeline-card-header">
                      <div className="timeline-card-kind">
                        <span className={`protocol protocol-${entry.kind === "alert" ? "dns" : entry.kind === "packet" ? "tls" : "tcp"}`}>{kindLabels[entry.kind]}</span>
                        {entry.severity && <SeverityBadge severity={entry.severity} />}
                      </div>
                      <time className="timeline-time"><Clock size={11} />{entry.timestamp}</time>
                    </div>
                    <strong className="timeline-headline">{entry.headline}</strong>
                    <p className="timeline-detail">{entry.detail}</p>
                    <div className="timeline-card-footer">
                      <span>{entry.source}</span>
                      {entry.destination && <span className="timeline-arrow">→ {entry.destination}</span>}
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
