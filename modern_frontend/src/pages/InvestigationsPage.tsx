import { FormEvent, useEffect, useMemo, useState } from "react";
import { Calendar, ClipboardPlus, Pencil, RefreshCw, Search, Trash2, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import type { InvestigationRecord, Severity } from "../types";
import { useT } from "../i18n/context";

const emptyForm: { title: string; status: "Open" | "Monitoring" | "Closed"; priority: Severity; hostIp: string; summary: string; notes: string } = { title: "", status: "Open", priority: "MEDIUM", hostIp: "", summary: "", notes: "" };

export function InvestigationsPage() {
  const t = useT();
  const [records, setRecords] = useState<InvestigationRecord[]>([]);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);

  const load = async () => {
    try {
      const { records: next } = await idsApi.investigations();
      setRecords(next);
      setNotice("");
    } catch {
      setNotice(t("investigations.unavailable"));
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
      if (editingId !== null) {
        await idsApi.updateInvestigation(editingId, form);
      } else {
        await idsApi.createInvestigation(form);
      }
      setForm(emptyForm);
      const savedId = editingId;
      setEditingId(null);
      await load();
      if (savedId !== null) setSelectedId(savedId);
      setNotice(savedId !== null ? t("investigations.updated") : t("investigations.created"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("investigations.createFailed"));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: number) => {
    try {
      await idsApi.deleteInvestigation(id);
      if (selectedId === id) setSelectedId(null);
      if (editingId === id) {
        setEditingId(null);
        setForm(emptyForm);
      }
      await load();
      setNotice(t("investigations.deleted"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("investigations.deleteFailed"));
    }
  };

  const edit = (record: InvestigationRecord) => {
    setEditingId(record.id);
    setForm({ title: record.title, status: record.status, priority: record.priority, hostIp: record.host_ip ?? "", summary: record.summary, notes: record.notes });
    setNotice("");
  };

  const cancelEdit = () => {
    setEditingId(null);
    setForm(emptyForm);
  };

  return (
    <div className="page-stack investigation-workspace">
      <section className="investigation-master">
        <div className="filter-row">
          <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("investigations.search")} /></label>
          <select className="plain-select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="All">{t("common.all")}</option><option>Open</option><option>Monitoring</option><option>Closed</option>
          </select>
          <button className="icon-button" type="button" title={t("common.refresh")} onClick={() => void load()}><RefreshCw size={15} /></button>
          <span className="result-count">{t("investigations.cases", { count: visible.length })}</span>
        </div>
        <div className="investigation-list">
          {visible.length ? visible.map((record) => (
            <div key={record.id} className={`investigation-card ${record.id === selectedId ? "selected" : ""}`} onClick={() => setSelectedId(record.id)}>
              <div>
                <h3>{record.title}</h3>
                <small>{record.host_ip ?? t("investigations.noHost")} · {record.status}</small>
                <p>{record.summary || t("investigations.noSummary")}</p>
              </div>
              <SeverityBadge severity={record.priority} />
            </div>
          )) : <p className="empty-state">{t("investigations.noInvestigations")}</p>}
        </div>
      </section>

      <aside className="investigation-detail">
        {selected ? (
          <>
            <header className="detail-header">
              <div>
                <SeverityBadge severity={selected.priority} />
                <h2>{selected.title}</h2>
                <p>{selected.host_ip ?? t("investigations.noHost")} · Created {selected.created_at}</p>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="icon-button" type="button" title={t("investigations.edit")} onClick={() => edit(selected)}><Pencil size={14} /></button>
                <button className="icon-button" type="button" title={t("investigations.deleteTitle")} onClick={() => void remove(selected.id)}><Trash2 size={14} /></button>
                <button className="icon-button" type="button" title={t("investigations.closeDetails")} onClick={() => setSelectedId(null)}><X size={17} /></button>
              </div>
            </header>
            <dl className="detail-grid">
              <div><dt>{t("investigations.status")}</dt><dd className={`status status-${selected.status === "Closed" ? "ignored" : selected.status === "Open" ? "unconfirmed" : "confirmed"}`}>{selected.status}</dd></div>
              <div><dt>{t("investigations.priority")}</dt><dd><SeverityBadge severity={selected.priority} /></dd></div>
              <div><dt>{t("investigations.lastUpdated")}</dt><dd>{selected.updated_at}</dd></div>
              <div><dt>{t("investigations.createdLabel")}</dt><dd>{selected.created_at}</dd></div>
            </dl>
            <div className="detail-section"><h3>{t("investigations.summaryLabel")}</h3><p>{selected.summary || t("investigations.noSummary")}</p></div>
            <div className="detail-section"><h3>{t("investigations.notesLabel")}</h3><p>{selected.notes || t("investigations.noNotes")}</p></div>
          </>
        ) : (
          <div className="empty-detail">
            <ClipboardPlus size={24} color="var(--muted)" />
            <p>{t("investigations.selectHint")}</p>
          </div>
        )}

        <form className="investigation-form-panel" onSubmit={submit} style={{ borderTop: "1px solid var(--border)", marginTop: selected ? 0 : "auto" }}>
          <header className="section-heading" style={{ padding: "0 0 8px", height: "auto", borderBottom: "none" }}><div><h2>{editingId === null ? t("investigations.new") : t("investigations.editTitle")}</h2><p>{t("investigations.persistHint")}</p></div></header>
          <input required placeholder={t("investigations.titlePlaceholder")} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <div className="form-row">
            <input placeholder={t("investigations.hostPlaceholder")} value={form.hostIp} onChange={(e) => setForm({ ...form, hostIp: e.target.value })} />
            <select value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value as Severity })}>
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((v) => <option key={v}>{v}</option>)}
            </select>
          </div>
          <select aria-label="Investigation status" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value as typeof form.status })}>
            {["Open", "Monitoring", "Closed"].map((value) => <option key={value}>{value}</option>)}
          </select>
          <textarea placeholder={t("investigations.summaryPlaceholder")} value={form.summary} onChange={(e) => setForm({ ...form, summary: e.target.value })} />
          <textarea placeholder={t("investigations.notesPlaceholder")} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          <div className="inline-actions">
            <button className="primary-button" type="submit" disabled={saving}>{editingId === null ? <ClipboardPlus size={15} /> : <Pencil size={15} />}{editingId === null ? t("investigations.create") : t("investigations.saveChanges")}</button>
            {editingId !== null && <button className="icon-text-button" type="button" onClick={cancelEdit}><X size={15} />{t("common.cancel")}</button>}
          </div>
          {notice && <p className="capture-notice" style={{ margin: 0 }}><Calendar size={14} />{notice}</p>}
        </form>
      </aside>
    </div>
  );
}
