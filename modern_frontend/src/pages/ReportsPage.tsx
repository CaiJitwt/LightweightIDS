import { useEffect, useMemo, useState } from "react";
import { Download, FileJson, FileText, FileSpreadsheet, CheckCircle2 } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import { SeverityBadge } from "../components/SeverityBadge";
import type { AlertRecord } from "../types";

export function ReportsPage({ refreshVersion }: { refreshVersion: number }) {
  const t = useT();
  const [notice, setNotice] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [records, setRecords] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    idsApi.alerts({}).then(({ records: next }) => {
      if (active) {
        setRecords(next);
        setNotice("");
      }
    }).catch((error) => {
      if (active) {
        setRecords([]);
        setNotice(error instanceof Error ? error.message : t("reports.unavailable"));
      }
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [refreshVersion]);

  const previewAlerts = useMemo(() => records.slice(0, 6), [records]);

  const stats = useMemo(() => {
    const critical = records.filter((a) => a.severity === "CRITICAL" || a.severity === "HIGH").length;
    const confirmed = records.filter((a) => a.status === "confirmed").length;
    return { total: records.length, critical, confirmed };
  }, [records]);

  const exportAlerts = async (kind: "csv" | "json" | "html") => {
    try {
      const { records } = await idsApi.alerts({});
      setRecords(records);
      const content = kind === "json" ? JSON.stringify(records, null, 2) : kind === "csv" ? toCsv(records) : toHtml(records);
      const blob = new Blob([content], { type: kind === "json" ? "application/json" : kind === "csv" ? "text/csv" : "text/html" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `lightweight-ids-alerts-${Date.now()}.${kind === "html" ? "html" : kind}`;
      link.click();
      URL.revokeObjectURL(link.href);
      setNotice(t("reports.exported", { count: records.length, format: kind.toUpperCase() }));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("reports.exportFailed"));
    }
  };

  return (
    <div className="page-stack">
      <section className="report-summary-strip">
        <div className="report-stat"><span>{t("reports.totalAlerts")}</span><strong>{stats.total}</strong><small>{t("reports.availableExport")}</small></div>
        <div className="report-stat"><span>{t("reports.highCritical")}</span><strong>{stats.critical}</strong><small>{t("reports.prioritized")}</small></div>
        <div className="report-stat"><span>{t("reports.confirmed")}</span><strong>{stats.confirmed}</strong><small>{t("reports.analystReviewed")}</small></div>
        <div className="report-stat"><span>{t("reports.exportFormats")}</span><strong>3</strong><small>{t("reports.formatsList")}</small></div>
      </section>

      <section className="section-panel">
        <header className="section-heading"><div><h2>{t("reports.exportTitle")}</h2><p>{t("reports.exportSubtitle")}</p></div><Download size={17} /></header>
        <div style={{ padding: 14 }}>
          <div className="report-export-grid">
            <button type="button" className="report-export-card" onClick={() => void exportAlerts("html")}>
              <div className="export-icon"><FileText size={20} /></div>
              <div><strong>{t("reports.htmlTitle")}</strong><p>{t("reports.htmlDesc")}</p></div>
              <footer><Download size={12} />{t("reports.exportHtml")}</footer>
            </button>
            <button type="button" className="report-export-card" onClick={() => void exportAlerts("csv")}>
              <div className="export-icon"><FileSpreadsheet size={20} /></div>
              <div><strong>{t("reports.csvTitle")}</strong><p>{t("reports.csvDesc")}</p></div>
              <footer><Download size={12} />{t("reports.exportCsv")}</footer>
            </button>
            <button type="button" className="report-export-card" onClick={() => void exportAlerts("json")}>
              <div className="export-icon"><FileJson size={20} /></div>
              <div><strong>{t("reports.jsonTitle")}</strong><p>{t("reports.jsonDesc")}</p></div>
              <footer><Download size={12} />{t("reports.exportJson")}</footer>
            </button>
          </div>
        </div>
      </section>

      {notice && <p className="capture-notice"><CheckCircle2 size={14} />{notice}</p>}

      <section className="section-panel">
        <header className="section-heading">
          <div><h2>{t("reports.alertPreview")}</h2><p>{t("reports.previewSubtitle")}</p></div>
          <button className="text-button" type="button" onClick={() => setShowPreview((v) => !v)}>{showPreview ? t("reports.hidePreview") : t("reports.showPreview")}</button>
        </header>
        {showPreview && (
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>{t("common.time")}</th><th>{t("rules.columnSeverity")}</th><th>{t("rules.columnRule")}</th><th>{t("alerts.source")}</th><th>{t("alerts.destination")}</th><th>{t("alerts.status")}</th></tr></thead>
              <tbody>
                {previewAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.timestamp}</td>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td style={{ maxWidth: 200 }}>{alert.ruleName}</td>
                    <td>{alert.source}</td>
                    <td>{alert.destination}</td>
                    <td><span className={`status status-${alert.status}`}>{alert.status}</span></td>
                  </tr>
                ))}
                {!previewAlerts.length && <tr><td colSpan={6} className="empty-table">{loading ? t("reports.loading") : t("reports.noAlerts")}</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function toCsv(records: AlertRecord[]) {
  const keys: (keyof AlertRecord)[] = ["id", "timestamp", "severity", "ruleName", "source", "destination", "protocol", "description", "evidence", "status"];
  return [keys.join(","), ...records.map((r) => keys.map((k) => `"${String(r[k] ?? "").replaceAll('"', '""')}"`).join(","))].join("\n");
}

function toHtml(records: AlertRecord[]) {
  const rows = records.map((r) => `<tr><td>${esc(r.timestamp)}</td><td>${esc(r.severity)}</td><td>${esc(r.ruleName)}</td><td>${esc(r.source)}</td><td>${esc(r.destination)}</td><td>${esc(r.status)}</td></tr>`).join("") || "<tr><td colspan=\"6\">No alerts</td></tr>";
  return `<!doctype html><html><head><meta charset="utf-8"><title>Lightweight IDS Alert Report</title><style>body{font-family:Inter,Segoe UI,Arial,sans-serif;margin:32px;color:#17212b}table{border-collapse:collapse;width:100%;font-size:13px}th,td{padding:10px 12px;border:1px solid #d9e0e7;text-align:left;vertical-align:top}th{background:#f2f5f7;font-weight:700}tr:nth-child(even){background:#fafbfc}</style></head><body><h1>Lightweight IDS Alert Report</h1><p>Exported ${new Date().toLocaleString()}</p><table><thead><tr><th>{t("common.time")}</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}

function esc(value: unknown) { return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }
