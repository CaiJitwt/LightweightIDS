import { useEffect, useMemo, useState } from "react";
import type { ColumnDef } from "@tanstack/react-table";
import { Ban, Check, ClipboardList, Search, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { DataTable } from "../components/DataTable";
import { DefenseAdvicePanel } from "../components/DefenseAdvicePanel";
import { SeverityBadge } from "../components/SeverityBadge";
import type { AlertRecord, AlertStatus, LlmSettings, PacketRecord, SecurityEventRecord } from "../types";
import { useLocale, useT } from "../i18n/context";

export function AlertsPage({ llmSettings, refreshVersion, initialAlertId, onAlertsChanged }: { llmSettings: LlmSettings; refreshVersion: number; initialAlertId?: number; onAlertsChanged: () => void }) {
  const t = useT();
  const locale = useLocale();
  const [records, setRecords] = useState<AlertRecord[]>([]);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState(t("common.allSeverities"));

  useEffect(() => {
    setSeverity((prev) => {
      if (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(prev)) return prev;
      return t("common.allSeverities");
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locale]);
  const [selectedId, setSelectedId] = useState<number | null>(initialAlertId ?? null);
  const [relatedPackets, setRelatedPackets] = useState<PacketRecord[]>([]);
  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [linkedSecurityEvent, setLinkedSecurityEvent] = useState<SecurityEventRecord | null>(null);
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
        .catch(() => {
          if (!active) return;
          setRecords([]);
          setSelectedId(null);
          setConnected(false);
        });
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
    idsApi.alertPackets(selected.id)
      .then(({ records: next }) => { if (active) setRelatedPackets(next); })
      .catch(() => { if (active) setRelatedPackets([]); });
    idsApi.alertSecurityEvent(selected.id)
      .then(({ record }) => { if (active) setLinkedSecurityEvent(record); })
      .catch(() => { if (active) setLinkedSecurityEvent(null); });
    return () => { active = false; };
  }, [selected]);

  const visible = useMemo(() => records.filter((alert) => {
    const text = `${alert.ruleName} ${alert.source} ${alert.destination} ${alert.description}`.toLowerCase();
    return (severity === t("common.allSeverities") || alert.severity === severity) && text.includes(query.toLowerCase());
  }), [query, records, severity, t]);
  const selectedPacket = relatedPackets.find((packet) => packet.id === selectedPacketId) ?? null;

  const columns = useMemo<ColumnDef<AlertRecord, unknown>[]>(() => [
    { accessorKey: "timestamp", header: t("common.time"), size: 155 },
    { accessorKey: "severity", header: t("common.severity"), size: 90, cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
    { accessorKey: "ruleName", header: t("common.rule"), size: 130 },
    { accessorKey: "source", header: t("alerts.source"), size: 135 },
    { accessorKey: "destination", header: t("alerts.destination"), size: 135 },
    { accessorKey: "description", header: t("common.description"), size: 200, enableSorting: false },
    { accessorKey: "status", header: t("alerts.status"), size: 90, cell: ({ getValue }) => <span className={`status status-${String(getValue())}`}>{String(getValue())}</span> },
  ], [t]);

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
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("alerts.search")} /></label>
        <select className="plain-select" value={severity} onChange={(event) => setSeverity(event.target.value)}><option>{t("common.allSeverities")}</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
        <span className="result-count">{t("alerts.count", { count: visible.length })} - {connected ? t("dashboard.localData") : t("alerts.localApiUnavailable")}</span>
      </section>
      <div className="master-detail">
        <section className="table-panel alert-master">
          <DataTable columns={columns} data={visible} getRowId={(row) => String(row.id)} selectedRowId={selected ? String(selected.id) : undefined} onRowClick={(row) => setSelectedId(row.id)} resizableColumns />
        </section>
        <aside className="detail-panel" aria-label="Selected alert details">
          {selected ? <>
            <header className="detail-header"><div><SeverityBadge severity={selected.severity} /><h2>{selected.ruleName}</h2><p>Alert #{selected.id} - {selected.timestamp}</p></div><button className="icon-button" type="button" title={t("alerts.closeDetails")} onClick={() => setSelectedId(null)}><X size={17} /></button></header>
            <dl className="detail-grid"><div><dt>{t("alerts.source")}</dt><dd>{selected.source}</dd></div><div><dt>{t("alerts.destination")}</dt><dd>{selected.destination}</dd></div><div><dt>{t("alerts.protocol")}</dt><dd>{selected.protocol}</dd></div><div><dt>{t("alerts.status")}</dt><dd className={`status status-${selected.status}`}>{selected.status}</dd></div></dl>
            <div className="detail-section"><h3>{t("alerts.analystSummary")}</h3><p>{selected.description}</p></div>
            <div className="detail-section"><h3>{t("alerts.evidence")}</h3><code>{selected.evidence}</code></div>
            {linkedSecurityEvent && <div className="detail-section host-event-evidence"><h3>{t("alerts.windowsEvent")}</h3><p>Event {linkedSecurityEvent.eventId} / Record {linkedSecurityEvent.recordId}</p><code>{JSON.stringify({ channel: linkedSecurityEvent.channel, computer: linkedSecurityEvent.computer, user: linkedSecurityEvent.user, sourceIp: linkedSecurityEvent.sourceIp, logonType: linkedSecurityEvent.logonType, processName: linkedSecurityEvent.processName, summary: linkedSecurityEvent.summary, details: linkedSecurityEvent.details }, null, 2)}</code></div>}
            <div className="detail-section"><h3>{t("alerts.relatedPackets")} <span>{relatedPackets.length}</span></h3><div className="packet-stack">{relatedPackets.map((packet) => <button type="button" className={packet.id === selectedPacketId ? "selected-packet" : ""} key={packet.id} onClick={() => setSelectedPacketId(packet.id)}><strong>#{packet.id} - {packet.timestamp}</strong><span>{packet.source} to {packet.destination}</span><small>{packet.summary}</small></button>)}{!relatedPackets.length && <p className="empty-packets">{t("alerts.noPackets")}</p>}</div>{selectedPacket && <div className="packet-metadata"><strong>{t("alerts.packetMetadata")}</strong><code>{JSON.stringify({ id: selectedPacket.id, timestamp: selectedPacket.timestamp, source: selectedPacket.source, destination: selectedPacket.destination, protocol: selectedPacket.protocol, length: selectedPacket.length, flags: selectedPacket.flags, summary: selectedPacket.summary, ...selectedPacket.details }, null, 2)}</code></div>}</div>
            <DefenseAdvicePanel alert={selected} settings={llmSettings} />
            <footer className="detail-actions"><button type="button" disabled={updating} onClick={() => updateStatus("confirmed")}><Check size={15} />{t("alerts.confirm")}</button><button type="button" disabled={updating} onClick={() => updateStatus("ignored")}><Ban size={15} />{t("alerts.ignore")}</button><button type="button" title={t("alerts.investigateTitle")}><ClipboardList size={15} />{t("alerts.investigate")}</button></footer>
          </> : <div className="empty-detail">{t("alerts.selectAlert")}</div>}
        </aside>
      </div>
    </div>
  );
}
