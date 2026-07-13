import { useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { CirclePause, CirclePlay, Download, Filter, Search } from "lucide-react";

import { DataTable } from "../components/DataTable";
import { packets } from "../data/mockData";
import type { PacketRecord } from "../types";

export function TrafficPage() {
  const [paused, setPaused] = useState(false);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All protocols");

  const visiblePackets = useMemo(() => packets.filter((packet) => {
    const matchesProtocol = protocol === "All protocols" || packet.protocol === protocol;
    const text = `${packet.source} ${packet.destination} ${packet.protocol} ${packet.summary}`.toLowerCase();
    return matchesProtocol && text.includes(query.toLowerCase());
  }), [protocol, query]);

  const columns = useMemo<ColumnDef<PacketRecord, unknown>[]>(() => [
    { accessorKey: "id", header: "ID", size: 64 },
    { accessorKey: "timestamp", header: "Time" },
    { accessorKey: "source", header: "Source" },
    { accessorKey: "destination", header: "Destination" },
    { accessorKey: "protocol", header: "Protocol", cell: ({ getValue }) => <span className={`protocol protocol-${String(getValue()).toLowerCase()}`}>{String(getValue())}</span> },
    { accessorKey: "length", header: "Bytes" },
    { accessorKey: "flags", header: "Flags" },
    { accessorKey: "summary", header: "Summary", enableSorting: false },
  ], []);

  return (
    <div className="page-stack">
      <section className="control-bar">
        <div className="capture-state"><span className={`live-dot ${paused ? "paused" : ""}`} />{paused ? "Capture paused" : "Capturing on Ethernet 3"}</div>
        <div className="control-actions">
          <button className="icon-text-button" type="button" onClick={() => setPaused((value) => !value)}>
            {paused ? <CirclePlay size={16} /> : <CirclePause size={16} />}{paused ? "Resume" : "Pause"}
          </button>
          <button className="icon-button" type="button" title="Export visible packets"><Download size={17} /></button>
        </div>
      </section>
      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter addresses, protocol or summary" /></label>
        <label className="select-box"><Filter size={15} /><select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option>All protocols</option><option>TLS</option><option>TCP</option><option>DNS</option><option>MDNS</option></select></label>
        <span className="result-count">{visiblePackets.length} packets shown</span>
      </section>
      <section className="table-panel grow-panel">
        <DataTable columns={columns} data={visiblePackets} getRowId={(row) => String(row.id)} />
      </section>
    </div>
  );
}
