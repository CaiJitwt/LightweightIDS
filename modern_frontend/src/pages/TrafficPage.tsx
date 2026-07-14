import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CirclePause, CirclePlay, Download, FileUp, Filter, Play, RefreshCw, Search, Square, WifiOff, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { DataTable } from "../components/DataTable";
import { packets as demoPackets } from "../data/mockData";
import type { CaptureStatus, PacketRecord, PcapImportStatus } from "../types";

const emptyStatus: CaptureStatus = {
  state: "stopped", interface: "Default interface", filterExpression: "", savePackets: true, detectionEnabled: true,
  packetTotal: 0, alertTotal: 0, skippedTotal: 0, savedPacketTotal: 0, savedAlertTotal: 0, packetsPerSecond: 0, error: "", nextSequence: 0,
};

const emptyPcapImport: PcapImportStatus = {
  state: "idle", filename: "", packetTotal: 0, alertTotal: 0, skippedTotal: 0, savedPacketTotal: 0, savedAlertTotal: 0, error: "",
};

const filterPresets = [
  { label: "All traffic", value: "" },
  { label: "TLS metadata", value: "tls" },
  { label: "DNS", value: "dns" },
  { label: "Internal TCP", value: "tcp and ip.addr == 10.0.0.0/8" },
  { label: "Web and DNS", value: "http or https or tls or dns" },
];

export function TrafficPage() {
  const [status, setStatus] = useState<CaptureStatus>(emptyStatus);
  const [serviceReady, setServiceReady] = useState(false);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [filterExpression, setFilterExpression] = useState("");
  const [filterNotice, setFilterNotice] = useState("");
  const [actionError, setActionError] = useState("");
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All protocols");
  const [livePackets, setLivePackets] = useState<PacketRecord[]>([]);
  const [selectedPacketKey, setSelectedPacketKey] = useState<string | null>(null);
  const [rateHistory, setRateHistory] = useState<{ time: string; rate: number; alerts: number }[]>([]);
  const [pcapImport, setPcapImport] = useState<PcapImportStatus>(emptyPcapImport);
  const cursor = useRef(0);
  const pcapPicker = useRef<HTMLInputElement>(null);

  const poll = useCallback(async () => {
    try {
      const [nextStatus, interfaceResponse, pcapResponse] = await Promise.all([idsApi.status(), idsApi.interfaces(), idsApi.pcapStatus()]);
      const packetResponse = await idsApi.packets(cursor.current);
      cursor.current = packetResponse.nextSequence;
      setStatus(nextStatus);
      setInterfaces(interfaceResponse.interfaces);
      setPcapImport(pcapResponse);
      setServiceReady(true);
      if (packetResponse.records.length) {
        setLivePackets((records) => [...packetResponse.records, ...records]
          .sort((left, right) => packetOrder(right) - packetOrder(left))
          .slice(0, 1_000));
      }
      setRateHistory((history) => [...history, { time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }), rate: nextStatus.packetsPerSecond, alerts: nextStatus.alertTotal }].slice(-60));
      if (nextStatus.error) setActionError(nextStatus.error);
    } catch {
      setServiceReady(false);
    }
  }, []);

  useEffect(() => {
    void poll();
    const timer = window.setInterval(() => void poll(), 750);
    return () => window.clearInterval(timer);
  }, [poll]);

  const displayedPackets = serviceReady ? livePackets : demoPackets;
  const visiblePackets = useMemo(() => displayedPackets.filter((packet) => {
    const matchesProtocol = protocol === "All protocols" || packet.protocol === protocol;
    const text = `${packet.source} ${packet.destination} ${packet.protocol} ${packet.summary}`.toLowerCase();
    return matchesProtocol && text.includes(query.toLowerCase());
  }), [displayedPackets, protocol, query]);
  const selectedPacket = displayedPackets.find((packet) => packetKey(packet) === selectedPacketKey) ?? null;

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

  const runAction = async (action: () => Promise<CaptureStatus>) => {
    setActionError("");
    try {
      setStatus(await action());
      await poll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The capture request failed.");
    }
  };

  const startCapture = () => runAction(async () => {
    setLivePackets([]);
    setSelectedPacketKey(null);
    cursor.current = 0;
    return idsApi.start({ interface: selectedInterface || null, filterExpression, savePackets: true, detectionEnabled: true, alertCooldownSeconds: 10 });
  });

  const validateFilter = async () => {
    setFilterNotice("");
    try {
      const result = await idsApi.validateFilter(filterExpression);
      setFilterNotice(result.bpf ? `Validated. Capture BPF: ${result.bpf}` : "Validated. No capture-side filter will be applied.");
    } catch (error) {
      setFilterNotice(error instanceof Error ? error.message : "Filter validation failed.");
    }
  };

  const importPcap = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setActionError("");
    try {
      setPcapImport(await idsApi.importPcap(file));
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The PCAP import request failed.");
    }
  };

  const exportPackets = () => {
    const header = "id,timestamp,source,destination,protocol,length,flags,summary";
    const rows = visiblePackets.map((packet) => [packet.id, packet.timestamp, packet.source, packet.destination, packet.protocol, packet.length, packet.flags, packet.summary].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","));
    const url = URL.createObjectURL(new Blob([[header, ...rows].join("\n")], { type: "text/csv" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "ids-visible-packets.csv";
    link.click();
    URL.revokeObjectURL(url);
  };

  const stateLabel = !serviceReady ? "Local capture service unavailable" : status.state === "running" ? `Capturing on ${status.interface}` : status.state === "paused" ? "Capture paused" : status.state === "error" ? "Capture error" : "Capture ready";
  const isActive = status.state === "running" || status.state === "paused" || status.state === "stopping";
  const pcapNotice = pcapImport.state === "importing" ? `Importing ${pcapImport.filename}: ${pcapImport.packetTotal.toLocaleString()} packets processed.` : pcapImport.state === "completed" ? `Imported ${pcapImport.filename}: ${pcapImport.savedPacketTotal.toLocaleString()} packets and ${pcapImport.savedAlertTotal.toLocaleString()} alerts stored.` : pcapImport.error;

  return (
    <div className="page-stack traffic-workspace">
      <section className="capture-control-panel">
        <input ref={pcapPicker} className="visually-hidden" type="file" accept=".pcap,.pcapng,.cap" onChange={importPcap} />
        <div className="capture-state"><span className={`live-dot ${status.state === "paused" || !serviceReady ? "paused" : ""}`} />{stateLabel}</div>
        <div className="capture-config">
          <label className="capture-field"><span>Interface</span><select aria-label="Capture interface" value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)} disabled={isActive || !serviceReady}><option value="">Default interface</option>{interfaces.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <label className="capture-field grow"><span>Capture filter</span><input value={filterExpression} onChange={(event) => setFilterExpression(event.target.value)} placeholder="tcp.port == 443 or dns" disabled={isActive || !serviceReady} /></label>
          <select aria-label="Capture filter preset" className="plain-select" value="" onChange={(event) => { if (event.target.value !== "") setFilterExpression(event.target.value); }} disabled={isActive || !serviceReady}><option value="">Presets</option>{filterPresets.map((preset) => <option key={preset.label} value={preset.value}>{preset.label}</option>)}</select>
          <button className="icon-button" type="button" title="Validate capture filter" onClick={() => void validateFilter()} disabled={isActive || !serviceReady}><Filter size={17} /></button>
        </div>
        <div className="control-actions">
          {!isActive && <button className="primary-button" type="button" onClick={() => void startCapture()} disabled={!serviceReady}><Play size={16} />Start capture</button>}
          {status.state === "running" && <button className="icon-text-button" type="button" onClick={() => void runAction(idsApi.pause)}><CirclePause size={16} />Pause</button>}
          {status.state === "paused" && <button className="icon-text-button" type="button" onClick={() => void runAction(idsApi.resume)}><CirclePlay size={16} />Resume</button>}
          {isActive && <button className="danger-button" type="button" onClick={() => void runAction(idsApi.stop)}><Square size={15} />Stop</button>}
          <button className="icon-text-button" type="button" onClick={() => pcapPicker.current?.click()} disabled={!serviceReady || pcapImport.state === "importing"}><FileUp size={16} />Import PCAP</button>
          <button className="icon-button" type="button" title="Refresh capture status" onClick={() => void poll()}><RefreshCw size={17} /></button>
          <button className="icon-button" type="button" title="Export visible packets" onClick={exportPackets}><Download size={17} /></button>
        </div>
      </section>

      <section className="capture-metrics" aria-label="Capture metrics"><Metric label="Packets" value={status.packetTotal.toLocaleString()} /><Metric label="Rate" value={`${status.packetsPerSecond.toFixed(1)}/s`} /><Metric label="Alerts" value={status.alertTotal.toLocaleString()} /><Metric label="Skipped" value={status.skippedTotal.toLocaleString()} /></section>
      {(actionError || filterNotice || pcapNotice || !serviceReady) && <p className={`capture-notice ${actionError || pcapImport.error ? "error" : ""}`}>{!serviceReady && <WifiOff size={15} />}{actionError || pcapNotice || filterNotice || "Start `python modern_main.py` from the project root to use the live capture controls. Demo records remain available offline."}</p>}

      <section className="traffic-chart-panel section-panel"><header className="section-heading"><div><h2>Capture throughput</h2><p>Rolling telemetry from the local capture service</p></div></header><div className="chart-area"><ResponsiveContainer width="100%" height="100%"><AreaChart data={rateHistory}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" /><XAxis dataKey="time" hide /><YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} /><Area type="monotone" dataKey="rate" name="Packets/s" stroke="#2878d0" fill="#dcecff" strokeWidth={2} isAnimationActive={false} /></AreaChart></ResponsiveContainer></div></section>

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter addresses, protocol or summary" /></label>
        <label className="select-box"><Filter size={15} /><select aria-label="Protocol" value={protocol} onChange={(event) => setProtocol(event.target.value)}><option>All protocols</option><option>TLS</option><option>TCP</option><option>DNS</option><option>MDNS</option></select></label>
        <span className="result-count">{visiblePackets.length} packets shown{serviceReady ? " from this session" : " from demo data"}</span>
      </section>
      <div className="master-detail traffic-packet-workspace">
        <section className="table-panel traffic-packet-table">
          <DataTable
            columns={columns}
            data={visiblePackets}
            getRowId={packetKey}
            selectedRowId={selectedPacketKey ?? undefined}
            onRowClick={(packet) => setSelectedPacketKey(packetKey(packet))}
          />
        </section>
        <aside className="detail-panel packet-detail-panel" aria-label="Selected packet details">
          {selectedPacket ? <>
            <header className="detail-header"><div><span className={`protocol protocol-${selectedPacket.protocol.toLowerCase()}`}>{selectedPacket.protocol}</span><h2>Packet #{selectedPacket.id}</h2><p>{selectedPacket.timestamp}</p></div><button className="icon-button" type="button" title="Close packet details" onClick={() => setSelectedPacketKey(null)}><X size={17} /></button></header>
            <dl className="detail-grid"><div><dt>Source</dt><dd title={selectedPacket.source}>{selectedPacket.source}</dd></div><div><dt>Destination</dt><dd title={selectedPacket.destination}>{selectedPacket.destination}</dd></div><div><dt>Length</dt><dd>{selectedPacket.length.toLocaleString()} bytes</dd></div><div><dt>TCP flags</dt><dd>{selectedPacket.flags || "-"}</dd></div></dl>
            <div className="detail-section"><h3>Packet summary</h3><p>{selectedPacket.summary || "No summary is available."}</p></div>
            <div className="detail-section packet-full-metadata"><h3>Complete stored metadata</h3><code>{JSON.stringify({ id: selectedPacket.id, sequence: selectedPacket.sequence, timestamp: selectedPacket.timestamp, source: selectedPacket.source, destination: selectedPacket.destination, protocol: selectedPacket.protocol, length: selectedPacket.length, flags: selectedPacket.flags, ...selectedPacket.details }, null, 2)}</code></div>
          </> : <div className="empty-detail">Select a packet to inspect its complete stored metadata.</div>}
        </aside>
      </div>
    </div>
  );
}

function packetKey(packet: PacketRecord): string {
  return String(packet.sequence ?? packet.id);
}

function packetOrder(packet: PacketRecord): number {
  return packet.sequence ?? packet.id;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><strong>{value}</strong></div>;
}
