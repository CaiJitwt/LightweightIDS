import { useState } from "react";
import { Download, FileJson, FileText, TableProperties } from "lucide-react";

import { idsApi } from "../api/idsApi";
import type { AlertRecord } from "../types";

export function ReportsPage() {
  const [notice, setNotice] = useState("Export current persisted alerts from the local API.");
  const exportAlerts = async (kind: "csv" | "json" | "html") => {
    try {
      const { records } = await idsApi.alerts();
      const content = kind === "json" ? JSON.stringify(records, null, 2) : kind === "csv" ? csv(records) : html(records);
      const blob = new Blob([content], { type: kind === "json" ? "application/json" : kind === "csv" ? "text/csv" : "text/html" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `lightweight-ids-alerts.${kind}`;
      link.click();
      URL.revokeObjectURL(link.href);
      setNotice(`${records.length} alerts exported as ${kind.toUpperCase()}.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Report export failed."); }
  };
  return <div className="page-stack reports-workspace"><section className="section-panel"><header className="section-heading"><div><h2>Reports</h2><p>Portable analyst exports from persisted alert records</p></div><Download size={17} /></header><div className="report-actions"><button type="button" onClick={() => void exportAlerts("html")}><FileText size={20} /><span><strong>HTML report</strong><small>Analyst-friendly overview</small></span></button><button type="button" onClick={() => void exportAlerts("csv")}><TableProperties size={20} /><span><strong>CSV export</strong><small>Spreadsheet-compatible alert list</small></span></button><button type="button" onClick={() => void exportAlerts("json")}><FileJson size={20} /><span><strong>JSON export</strong><small>Structured integration data</small></span></button></div><p className="page-note">{notice}</p></section></div>;
}

function csv(records: AlertRecord[]) { const keys: (keyof AlertRecord)[] = ["id", "timestamp", "severity", "ruleName", "source", "destination", "protocol", "description", "evidence", "status"]; return [keys.join(","), ...records.map((record) => keys.map((key) => `"${String(record[key] ?? "").replaceAll('"', '""')}"`).join(","))].join("\n"); }
function html(records: AlertRecord[]) { return `<!doctype html><html><head><meta charset="utf-8"><title>Lightweight IDS Alert Report</title><style>body{font-family:Arial;margin:32px;color:#17212b}table{border-collapse:collapse;width:100%}th,td{padding:8px;border:1px solid #d9e0e7;text-align:left;vertical-align:top}th{background:#f2f5f7}</style></head><body><h1>Lightweight IDS Alert Report</h1><p>Exported ${new Date().toLocaleString()}</p><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Description</th><th>Status</th></tr></thead><tbody>${records.map((record) => `<tr><td>${esc(record.timestamp)}</td><td>${esc(record.severity)}</td><td>${esc(record.ruleName)}</td><td>${esc(record.source)}</td><td>${esc(record.destination)}</td><td>${esc(record.description)}</td><td>${esc(record.status)}</td></tr>`).join("") || "<tr><td colspan=\"7\">No alerts</td></tr>"}</tbody></table></body></html>`; }
function esc(value: unknown) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }
