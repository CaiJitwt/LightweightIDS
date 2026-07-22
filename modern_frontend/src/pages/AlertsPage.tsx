import { useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Ban, Check, ClipboardList, Search, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { DataTable } from "../components/DataTable";
import { DefenseAdvicePanel } from "../components/DefenseAdvicePanel";
import { SeverityBadge } from "../components/SeverityBadge";
import { alerts as initialAlerts, packets as previewPackets } from "../data/mockData";
import type { AlertRecord, AlertStatus, LlmSettings, PacketRecord, SecurityEventRecord } from "../types";

export function AlertsPage({ llmSettings, refreshVersion, initialAlertId, onAlertsChanged }: { llmSettings: LlmSettings; refreshVersion: number; initialAlertId?: number; onAlertsChanged: () => void }) {
  const [records, setRecords] = useState<AlertRecord[]>(initialAlerts);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [selectedId, setSelectedId] = useState<number | null>(initialAlertId ?? initialAlerts[0]?.id ?? null);
  const [relatedPackets, setRelatedPackets] = useState<PacketRecord[]>([]);
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [linkedSecurityEvent, setLinkedSecurityEvent] = useState<SecurityEventRecord | null>(null);
  const [relatedFallback, setRelatedFallback] = useState(false);
  const [connected, setConnected] = useState(false);
  const [updating, setUpdating] = useState(false);

  useEffect(() => { if (initialAlertId !== undefined) setSelectedId(initialAlertId); }, [initialAlertId]);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      idsApi.alerts({ query, severity })
        .then(({ records: next }) => {
          if (!active) return;
          setRecords(next);
          setConnected(true);
          setSelectedId((current) => next.some((alert) => alert.id === current) ? current : next[0]?.id ?? null);
        })
        .catch(() => { if (active) setConnected(false); });
    }, query ? 180 : 0);
    return () => { active = false; window.clearTimeout(timer); };
  }, [query, refreshVersion, severity]);

  const selected = records.find((alert) => alert.id === selectedId) ?? null;
  useEffect(() => {
    if (!selected) {
      setRelatedPackets([]);
      setLinkedSecurityEvent(null);
      return;
    }
    let active = true;
    setSelectedPacketId(null);
    setLinkedSecurityEvent(null);
    setRelatedFallback(false);
    idsApi.alertPackets(selected.id)
      .then(({ records: next }) => { if (active) setRelatedPackets(next); })
      .catch(() => {
        if (active) { setRelatedPackets(previewPackets.filter((packet) => selected.packetIds?.includes(packet.id))); setRelatedFallback(true); }
      });
    idsApi.alertSecurityEvent(selected.id)
      .then(({ record }) => { if (active) setLinkedSecurityEvent(record); })
      .catch(() => { if (active) setLinkedSecurityEvent(null); });
    return () => { active = false; };
  }, [selected]);

  const visible = useMemo(() => records.filter((alert) => {
    const text = `${alert.ruleName} ${alert.source} ${alert.destination} ${alert.description}`.toLowerCase();
    return (severity === "All severities" || alert.severity === severity) && text.includes(query.toLowerCase());
  }), [query, records, severity]);
  const selectedPacket = relatedPackets.find((packet) => packet.id === selectedPacketId) ?? null;

  const columns = useMemo<ColumnDef<AlertRecord, unknown>[]>(() => [
    { accessorKey: "timestamp", header: "Time", size: 155 },
    { accessorKey: "severity", header: "Severity", size: 90, cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { accessorKey: "ruleName", header: "Rule", size: 130 },
    { accessorKey: "source", header: "Source", size: 135 },
    { accessorKey: "destination", header: "Destination", size: 135 },
    { accessorKey: "description", header: "Description", size: 200, enableSorting: false },
    { accessorKey: "status", header: "Status", size: 90, cell: ({ getValue }) => <span className={`status status-${String(getValue())}`}>{String(getValue())}</span> },
  ], []);

  const updateStatus = async (status: AlertStatus) => {
    if (!selected || updating) return;
    setUpdating(true);
    try {
      const { record } = await idsApi.updateAlertStatus(selected.id, status);
      setRecords((items) => items.map((item) => item.id === record.id ? record : item));
      onAlertsChanged();
    } catch {
      setRecords((items) => items.map((item) => item.id === selected.id ? { ...item, status } : item));
    } finally {
      setUpdating(false);
    }
  };

  return (
    <div className="page-stack alert-workspace">
      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search alerts, hosts or descriptions" /></label>
        <select className="plain-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
        <span className="result-count">{visible.length} alerts - {connected ? "Local SQLite data" : "Offline preview"}</span>
      </section>
      <div className="master-detail">
        <section className="table-panel alert-master">
          <DataTable columns={columns} data={visible} getRowId={(row) => String(row.id)} selectedRowId={selected ? String(selected.id) : undefined} onRowClick={(row) => setSelectedId(row.id)} resizableColumns />
        </section>
        <aside className="detail-panel" aria-label="Selected alert details">
          {selected ? <>
            <header className="detail-header"><div><SeverityBadge severity={selected.severity} /><h2>{selected.ruleName}</h2><p>Alert #{selected.id} - {selected.timestamp}</p></div><button className="icon-button" type="button" title="Close details" onClick={() => setSelectedId(null)}><X size={17} /></button></header>
            <dl className="detail-grid"><div><dt>Source</dt><dd>{selected.source}</dd></div><div><dt>Destination</dt><dd>{selected.destination}</dd></div><div><dt>Protocol</dt><dd>{selected.protocol}</dd></div><div><dt>Status</dt><dd className={`status status-${selected.status}`}>{selected.status}</dd></div></dl>
            <div className="detail-section"><h3>Analyst summary</h3><p>{selected.description}</p></div>
            <div className="detail-section"><h3>Evidence</h3><code>{selected.evidence}</code></div>
            {linkedSecurityEvent && <div className="detail-section host-event-evidence"><h3>Windows security event</h3><p>Event {linkedSecurityEvent.eventId} / Record {linkedSecurityEvent.recordId}</p><code>{JSON.stringify({ channel: linkedSecurityEvent.channel, computer: linkedSecurityEvent.computer, user: linkedSecurityEvent.user, sourceIp: linkedSecurityEvent.sourceIp, logonType: linkedSecurityEvent.logonType, processName: linkedSecurityEvent.processName, summary: linkedSecurityEvent.summary, details: linkedSecurityEvent.details }, null, 2)}</code></div>}
            <div className="detail-section"><h3>Related packets <span>{relatedPackets.length}</span>{relatedFallback && <span className="capture-notice" style={{display: "inline-flex", marginLeft: 8, padding: "2px 6px", fontSize: 11}}>Preview</span>}</h3><div className="packet-stack">{relatedPackets.map((packet) => <button type="button" className={packet.id === selectedPacketId ? "selected-packet" : ""} key={packet.id} onClick={() => setSelectedPacketId(packet.id)}><strong>#{packet.id} - {packet.timestamp}</strong><span>{packet.source} to {packet.destination}</span><small>{packet.summary}</small></button>)}{!relatedPackets.length && <p className="empty-packets">No persisted packets match this alert window.</p>}</div>{selectedPacket && <div className="packet-metadata"><strong>Packet metadata</strong><code>{JSON.stringify({ id: selectedPacket.id, timestamp: selectedPacket.timestamp, source: selectedPacket.source, destination: selectedPacket.destination, protocol: selectedPacket.protocol, length: selectedPacket.length, flags: selectedPacket.flags, summary: selectedPacket.summary, ...selectedPacket.details }, null, 2)}</code></div>}</div>
            <DefenseAdvicePanel alert={selected} settings={llmSettings} />
            <footer className="detail-actions"><button type="button" disabled={updating} onClick={() => updateStatus("confirmed")}><Check size={15} />Confirm</button><button type="button" disabled={updating} onClick={() => updateStatus("ignored")}><Ban size={15} />Ignore</button><button type="button" title="Investigation workflows remain available in the PySide application"><ClipboardList size={15} />Investigate</button></footer>
          </> : <div className="empty-detail">Select an alert to review its evidence and related packets.</div>}
        </aside>
      </div>
    </div>
  );
}
