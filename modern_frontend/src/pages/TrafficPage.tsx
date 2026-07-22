import { useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { CirclePause, CirclePlay, Download, FileUp, Filter, Play, RefreshCw, Search, Square, WifiOff, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import type { TranslationKey } from "../i18n/translations";
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

const filterPresets: Array<{ labelKey: TranslationKey; value: string }> = [
  { labelKey: "traffic.presetAllTraffic", value: "" },
  { labelKey: "traffic.presetTls", value: "tls" },
  { labelKey: "traffic.presetDns", value: "dns" },
  { labelKey: "traffic.presetInternalTcp", value: "tcp and ip.addr == 10.0.0.0/8" },
  { labelKey: "traffic.presetWebDns", value: "http or https or tls or dns" },
];

export function TrafficPage({ onDataChanged }: { onDataChanged?: () => void }) {
  const t = useT();
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
  const notifiedImport = useRef("");

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
        setLivePackets((records) => {
          const merged = new Map<string, PacketRecord>();
          for (const packet of [...packetResponse.records, ...records]) {
            merged.set(packetKey(packet), packet);
          }
          return [...merged.values()]
            .sort((left, right) => packetOrder(right) - packetOrder(left))
            .slice(0, 1_000);
        });
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

  useEffect(() => {
    if (pcapImport.state === "importing") {
      notifiedImport.current = "";
      return;
    }
    if (pcapImport.state !== "completed") return;
    const key = `${pcapImport.filename}:${pcapImport.savedPacketTotal}:${pcapImport.savedAlertTotal}`;
    if (notifiedImport.current === key) return;
    notifiedImport.current = key;
    onDataChanged?.();
  }, [onDataChanged, pcapImport]);

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
    { accessorKey: "source", header: t("traffic.source") },
    { accessorKey: "destination", header: t("traffic.destination") },
    { accessorKey: "protocol", header: t("alerts.protocol"), cell: ({ getValue }) => <span className={`protocol protocol-${String(getValue()).toLowerCase()}`}>{String(getValue())}</span> },
    { accessorKey: "length", header: t("traffic.bytes") },
    { accessorKey: "flags", header: "Flags" },
    { accessorKey: "summary", header: t("investigations.summaryLabel"), enableSorting: false },
  ], [t]);

  const runAction = async (action: () => Promise<CaptureStatus>) => {
    setActionError("");
    try {
      setStatus(await action());
      await poll();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : t("traffic.requestFailed"));
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
      setFilterNotice(result.bpf ? t("traffic.validated", { bpf: result.bpf }) : t("traffic.validatedNoFilter"));
    } catch (error) {
      setFilterNotice(error instanceof Error ? error.message : t("traffic.filterFailed"));
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
      setActionError(error instanceof Error ? error.message : t("traffic.importFailed"));
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

  const stateLabel = !serviceReady ? t("traffic.captureUnavailable") : status.state === "running" ? t("traffic.capturingOn", { interface: status.interface === "Default interface" ? t("traffic.defaultInterface") : status.interface }) : status.state === "paused" ? t("traffic.capturePaused") : status.state === "error" ? t("traffic.captureError") : t("traffic.captureReady");
  const isActive = status.state === "running" || status.state === "paused" || status.state === "stopping";
  const pcapNotice = pcapImport.state === "importing" ? t("traffic.importing", { filename: pcapImport.filename, count: pcapImport.packetTotal.toLocaleString() }) : pcapImport.state === "completed" ? t("traffic.imported", { filename: pcapImport.filename, packets: pcapImport.savedPacketTotal.toLocaleString(), alerts: pcapImport.savedAlertTotal.toLocaleString() }) : pcapImport.error;

  return (
    <div className="page-stack traffic-workspace">
      <section className="capture-control-panel">
        <input ref={pcapPicker} className="visually-hidden" type="file" accept=".pcap,.pcapng,.cap" onChange={importPcap} />
        <div className="capture-state"><span className={`live-dot ${status.state === "paused" || !serviceReady ? "paused" : ""}`} />{stateLabel}</div>
        <div className="capture-config">
          <label className="capture-field"><span>{t("traffic.interface")}</span><select aria-label={t("traffic.interface")} value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)} disabled={isActive || !serviceReady}><option value="">{t("traffic.defaultInterface")}</option>{interfaces.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
          <label className="capture-field grow"><span>{t("traffic.captureFilter")}</span><input value={filterExpression} onChange={(event) => setFilterExpression(event.target.value)} placeholder={t("traffic.filterPlaceholder")} disabled={isActive || !serviceReady} /></label>
          <select aria-label="Capture filter preset" className="plain-select" value="" onChange={(event) => { if (event.target.value !== "") setFilterExpression(event.target.value); }} disabled={isActive || !serviceReady}><option value="">{t("traffic.filterPresets")}</option>{filterPresets.map((preset) => <option key={preset.labelKey} value={preset.value}>{t(preset.labelKey)}</option>)}</select>
          <button className="icon-button" type="button" title={t("traffic.validateFilter")} onClick={() => void validateFilter()} disabled={isActive || !serviceReady}><Filter size={17} /></button>
        </div>
        <div className="control-actions">
          {!isActive && <button className="primary-button" type="button" onClick={() => void startCapture()} disabled={!serviceReady}><Play size={16} />{t("traffic.startCapture")}</button>}
          {status.state === "running" && <button className="icon-text-button" type="button" onClick={() => void runAction(idsApi.pause)}><CirclePause size={16} />{t("traffic.pause")}</button>}
          {status.state === "paused" && <button className="icon-text-button" type="button" onClick={() => void runAction(idsApi.resume)}><CirclePlay size={16} />{t("traffic.resume")}</button>}
          {isActive && <button className="danger-button" type="button" onClick={() => void runAction(idsApi.stop)}><Square size={15} />{t("traffic.stop")}</button>}
          <button className="icon-text-button" type="button" onClick={() => pcapPicker.current?.click()} disabled={!serviceReady || pcapImport.state === "importing"}><FileUp size={16} />{t("traffic.importPcap")}</button>
          <button className="icon-button" type="button" title={t("traffic.refreshStatus")} onClick={() => void poll()}><RefreshCw size={17} /></button>
          <button className="icon-button" type="button" title={t("traffic.exportPackets")} onClick={exportPackets}><Download size={17} /></button>
        </div>
      </section>

      <section className="capture-metrics" aria-label="Capture metrics"><Metric label={t("traffic.packets")} value={status.packetTotal.toLocaleString()} /><Metric label={t("traffic.rate")} value={`${status.packetsPerSecond.toFixed(1)}/s`} /><Metric label={t("traffic.alerts")} value={status.alertTotal.toLocaleString()} /><Metric label={t("traffic.skipped")} value={status.skippedTotal.toLocaleString()} /></section>
      {(actionError || filterNotice || pcapNotice || !serviceReady) && <p className={`capture-notice ${actionError || pcapImport.error ? "error" : ""}`}>{!serviceReady && <WifiOff size={15} />}{actionError || pcapNotice || filterNotice || t("traffic.demoNotice")}</p>}

      <section className="traffic-chart-panel section-panel"><header className="section-heading"><div><h2>{t("traffic.throughput")}</h2><p>{t("traffic.throughputMeta")}</p></div></header><div className="chart-area"><ResponsiveContainer width="100%" height="100%"><AreaChart data={rateHistory}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="var(--chart-grid)" /><XAxis dataKey="time" hide /><YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11 }} /><Tooltip contentStyle={{ borderRadius: 6, borderColor: "var(--border)" }} /><Area type="monotone" dataKey="rate" name="Packets/s" stroke="#2878d0" fill="#dcecff" strokeWidth={2} isAnimationActive={false} /></AreaChart></ResponsiveContainer></div></section>

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("traffic.filterAddresses")} /></label>
        <label className="select-box"><Filter size={15} /><select aria-label={t("alerts.protocol")} value={protocol} onChange={(event) => setProtocol(event.target.value)}><option value="All protocols">{t("common.allProtocols")}</option><option value="TLS">TLS</option><option value="TCP">TCP</option><option value="DNS">DNS</option><option value="MDNS">MDNS</option></select></label>
        <span className="result-count">{serviceReady ? t("traffic.shownLive", { count: visiblePackets.length }) : t("traffic.shownDemo", { count: visiblePackets.length })}</span>
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
            <header className="detail-header"><div><span className={`protocol protocol-${selectedPacket.protocol.toLowerCase()}`}>{selectedPacket.protocol}</span><h2>Packet #{selectedPacket.id}</h2><p>{selectedPacket.timestamp}</p></div><button className="icon-button" type="button" title={t("traffic.closeDetails")} onClick={() => setSelectedPacketKey(null)}><X size={17} /></button></header>
            <dl className="detail-grid"><div><dt>{t("traffic.source")}</dt><dd title={selectedPacket.source}>{selectedPacket.source}</dd></div><div><dt>{t("traffic.destination")}</dt><dd title={selectedPacket.destination}>{selectedPacket.destination}</dd></div><div><dt>{t("traffic.length")}</dt><dd>{selectedPacket.length.toLocaleString()} {t("traffic.bytes")}</dd></div><div><dt>{t("traffic.tcpFlags")}</dt><dd>{selectedPacket.flags || "-"}</dd></div></dl>
            <div className="detail-section"><h3>{t("traffic.packetSummary")}</h3><p>{selectedPacket.summary || t("traffic.noSummary")}</p></div>
            <div className="detail-bottom">
              <div className="detail-section packet-full-metadata"><h3>{t("traffic.completeMetadata")}</h3><code>{JSON.stringify({ id: selectedPacket.id, sequence: selectedPacket.sequence, timestamp: selectedPacket.timestamp, source: selectedPacket.source, destination: selectedPacket.destination, protocol: selectedPacket.protocol, length: selectedPacket.length, flags: selectedPacket.flags, ...selectedPacket.details }, null, 2)}</code></div>
              {selectedPacket.rawHex && <HexDump hex={selectedPacket.rawHex} />}
            </div>
          </> : <div className="empty-detail">{t("traffic.selectPacket")}</div>}
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

function HexDump({ hex }: { hex: string }) {
  const lines: { offset: string; hex: string; ascii: string }[] = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const bytes: string[] = [];
    let ascii = "";
    for (let j = 0; j < chunk.length; j += 2) {
      const byte = chunk.slice(j, j + 2);
      bytes.push(byte);
      const code = parseInt(byte, 16);
      ascii += code >= 32 && code <= 126 ? String.fromCharCode(code) : ".";
    }
    const hexPart = bytes.slice(0, 8).join(" ") + "  " + bytes.slice(8).join(" ");
    lines.push({ offset: i.toString(16).padStart(4, "0"), hex: hexPart, ascii });
  }
  return (
    <div className="detail-section hex-dump-section">
      <h3>Packet Bytes (Hex / ASCII)</h3>
      <pre className="hex-dump">{lines.map((line) => (
        <span key={line.offset}>{line.offset}  {line.hex.padEnd(49)}  {line.ascii}{"\n"}</span>
      ))}</pre>
    </div>
  );
}
