import { FormEvent, useEffect, useMemo, useState } from "react";
import { Calendar, ClipboardPlus, RefreshCw, Search, Trash2, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import type { InvestigationRecord, Severity } from "../types";

const emptyForm: { title: string; status: "Open" | "Monitoring" | "Closed"; priority: Severity; hostIp: string; summary: string; notes: string } = { title: "", status: "Open", priority: "MEDIUM", hostIp: "", summary: "", notes: "" };

export function InvestigationsPage() {
  const [records, setRecords] = useState<InvestigationRecord[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);

  const load = async () => {
    try {
      const { records: next } = await idsApi.investigations();
      setRecords(next);
      setNotice("");
    } catch {
      setNotice("Local API unavailable. Investigations are read-only previews.");
    }
  };
  useEffect(() => { void load(); }, []);

  const visible = useMemo(() => {
    return records.filter((r) => {
      const matchesStatus = statusFilter === "All" || r.status === statusFilter;
      const q = query.toLowerCase();
      return matchesStatus && (query.trim() === "" || r.title.toLowerCase().includes(q) || r.summary.toLowerCase().includes(q) || (r.host_ip ?? "").includes(q));
    });
  }, [records, query, statusFilter]);

  const selected = records.find((r) => r.id === selectedId) ?? null;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    try {
      await idsApi.createInvestigation(form);
      setForm(emptyForm);
      setNotice("Investigation created.");
      await load();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not create investigation.");
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    await idsApi.deleteInvestigation(id);
    if (selectedId === id) setSelectedId(null);
    await load();
  };

  const openCount = records.filter((r) => r.status === "Open").length;

  return (
    <div className="page-stack investigation-workspace">
      <section className="investigation-master">
        <div className="filter-row">
          <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search investigations…" /></label>
          <select className="plain-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option>All</option><option>Open</option><option>Monitoring</option><option>Closed</option>
          </select>
          <button className="icon-button" type="button" title="Refresh" onClick={() => void load()}><RefreshCw size={15} /></button>
          <span className="result-count">{visible.length} cases</span>
        </div>
        <div className="investigation-list">
          {visible.length ? visible.map((record) => (
            <div key={record.id} className={`investigation-card ${record.id === selectedId ? "selected" : ""}`} onClick={() => setSelectedId(record.id)}>
              <div>
                <h3>{record.title}</h3>
                <small>{record.host_ip ?? "No host"} · {record.status}</small>
                <p>{record.summary || "No summary provided."}</p>
              </div>
              <SeverityBadge severity={record.priority} />
            </div>
          )) : <p className="empty-state">No investigations match the current filters.</p>}
        </div>
      </section>

      <aside className="investigation-detail">
        {selected ? (
          <>
            <header className="detail-header">
              <div>
                <SeverityBadge severity={selected.priority} />
                <h2>{selected.title}</h2>
                <p>{selected.host_ip ?? "No host"} · Created {selected.created_at}</p>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="icon-button" type="button" title="Delete investigation" onClick={() => void remove(selected.id)}><Trash2 size={14} /></button>
                <button className="icon-button" type="button" title="Close details" onClick={() => setSelectedId(null)}><X size={17} /></button>
              </div>
            </header>
            <dl className="detail-grid">
              <div><dt>Status</dt><dd className={`status status-${selected.status === "Closed" ? "ignored" : selected.status === "Open" ? "unconfirmed" : "confirmed"}`}>{selected.status}</dd></div>
              <div><dt>Priority</dt><dd><SeverityBadge severity={selected.priority} /></dd></div>
              <div><dt>Last Updated</dt><dd>{selected.updated_at}</dd></div>
              <div><dt>Created</dt><dd>{selected.created_at}</dd></div>
            </dl>
            <div className="detail-section"><h3>Summary</h3><p>{selected.summary || "No summary provided."}</p></div>
            <div className="detail-section"><h3>Notes</h3><p>{selected.notes || "No notes recorded."}</p></div>
          </>
        ) : (
          <div className="empty-detail">
            <ClipboardPlus size={24} color="var(--muted)" />
            <p>Select an investigation to view details,<br />or create a new one below.</p>
          </div>
        )}

        <form className="investigation-form-panel" onSubmit={submit} style={{ borderTop: "1px solid var(--border)", marginTop: selected ? 0 : "auto" }}>
          <header className="section-heading" style={{ padding: "0 0 8px", height: "auto", borderBottom: "none" }}><div><h2>New investigation</h2><p>Capture alert evidence before it expires</p></div></header>
          <input required placeholder="Investigation title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <div className="form-row">
            <input placeholder="Host IP (optional)" value={form.hostIp} onChange={(e) => setForm({ ...form, hostIp: e.target.value })} />
            <select value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value as Severity })}>
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((v) => <option key={v}>{v}</option>)}
            </select>
          </div>
          <textarea placeholder="Summary" value={form.summary} onChange={(e) => setForm({ ...form, summary: e.target.value })} />
          <textarea placeholder="Notes" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          <button className="primary-button" type="submit" disabled={saving}><ClipboardPlus size={15} />Create investigation</button>
          {notice && <p className="capture-notice" style={{ margin: 0 }}><Calendar size={14} />{notice}</p>}
        </form>
      </aside>
    </div>
  );
}
