import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Ban, Check, ClipboardList, Search, X } from "lucide-react";

import { DataTable } from "../components/DataTable";
import { SeverityBadge } from "../components/SeverityBadge";
import { alerts as initialAlerts, packets } from "../data/mockData";
import type { AlertRecord, AlertStatus } from "../types";

export function AlertsPage() {
  const [records, setRecords] = useState(initialAlerts);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("All severities");
  const [selectedId, setSelectedId] = useState(initialAlerts[0].id);
  const selected = records.find((alert) => alert.id === selectedId) ?? records[0];

  const visible = useMemo(() => records.filter((alert) => {
    const text = `${alert.ruleName} ${alert.source} ${alert.destination} ${alert.description}`.toLowerCase();
    return (severity === "All severities" || alert.severity === severity) && text.includes(query.toLowerCase());
  }), [query, records, severity]);

  const columns = useMemo<ColumnDef<AlertRecord, unknown>[]>(() => [
    { accessorKey: "timestamp", header: "Time" },
    { accessorKey: "severity", header: "Severity", cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { accessorKey: "ruleName", header: "Rule" },
    { accessorKey: "source", header: "Source" },
    { accessorKey: "destination", header: "Destination" },
    { accessorKey: "description", header: "Description", enableSorting: false },
    { accessorKey: "status", header: "Status", cell: ({ getValue }) => <span className={`status status-${String(getValue())}`}>{String(getValue())}</span> },
  ], []);

  const updateStatus = (status: AlertStatus) => {
    setRecords((items) => items.map((item) => item.id === selected.id ? { ...item, status } : item));
  };
  const relatedPackets = packets.filter((packet) => selected.packetIds.includes(packet.id));

  return (
    <div className="page-stack alert-workspace">
      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search alerts, hosts or descriptions" /></label>
        <select className="plain-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option>All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <span className="result-count">{visible.length} alerts</span>
      </section>
      <div className="master-detail">
        <section className="table-panel alert-master">
          <DataTable columns={columns} data={visible} getRowId={(row) => String(row.id)} selectedRowId={String(selected.id)} onRowClick={(row) => setSelectedId(row.id)} />
        </section>
        <aside className="detail-panel" aria-label="Selected alert details">
          <header className="detail-header"><div><SeverityBadge severity={selected.severity} /><h2>{selected.ruleName}</h2><p>Alert #{selected.id} - {selected.timestamp}</p></div><button className="icon-button" type="button" title="Close details"><X size={17} /></button></header>
          <dl className="detail-grid"><div><dt>Source</dt><dd>{selected.source}</dd></div><div><dt>Destination</dt><dd>{selected.destination}</dd></div><div><dt>Protocol</dt><dd>{selected.protocol}</dd></div><div><dt>Status</dt><dd className={`status status-${selected.status}`}>{selected.status}</dd></div></dl>
          <div className="detail-section"><h3>Analyst summary</h3><p>{selected.description}</p></div>
          <div className="detail-section"><h3>Evidence</h3><code>{selected.evidence}</code></div>
          <div className="detail-section"><h3>Related packets <span>{relatedPackets.length}</span></h3><div className="packet-stack">{relatedPackets.map((packet) => <div key={packet.id}><strong>#{packet.id} - {packet.timestamp}</strong><span>{packet.source} to {packet.destination}</span><small>{packet.summary}</small></div>)}</div></div>
          <footer className="detail-actions"><button type="button" onClick={() => updateStatus("confirmed")}><Check size={15} />Confirm</button><button type="button" onClick={() => updateStatus("ignored")}><Ban size={15} />Ignore</button><button type="button"><ClipboardList size={15} />Investigate</button></footer>
        </aside>
      </div>
    </div>
  );
}
