import { FormEvent, useEffect, useState } from "react";
import { ClipboardPlus, RefreshCw, Trash2 } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import type { InvestigationRecord } from "../types";

const emptyForm = { title: "", status: "Open", priority: "MEDIUM", hostIp: "", summary: "", notes: "" };

export function InvestigationsPage() {
  const [records, setRecords] = useState<InvestigationRecord[]>([]);
  const [form, setForm] = useState(emptyForm);
  const [notice, setNotice] = useState("Capture alert evidence before it is cleared from the main queue.");
  const load = () => idsApi.investigations().then(({ records: next }) => setRecords(next)).catch(() => setNotice("Local API unavailable. Investigations are read-only in this preview."));
  useEffect(() => { void load(); }, []);
  const submit = async (event: FormEvent) => { event.preventDefault(); try { await idsApi.createInvestigation(form); setForm(emptyForm); setNotice("Investigation created."); await load(); } catch (error) { setNotice(error instanceof Error ? error.message : "Could not create investigation."); } };
  const remove = async (id: number) => { await idsApi.deleteInvestigation(id); await load(); };
  return <div className="page-stack"><section className="section-panel"><header className="section-heading"><div><h2>Investigations</h2><p>Analyst notes and evidence snapshots survive alert resets.</p></div><button className="icon-button" type="button" title="Refresh investigations" onClick={() => void load()}><RefreshCw size={15} /></button></header><form className="investigation-form" onSubmit={submit}><input required aria-label="Investigation title" placeholder="Investigation title" value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} /><input aria-label="Host IP" placeholder="Host IP (optional)" value={form.hostIp} onChange={(event) => setForm({ ...form, hostIp: event.target.value })} /><select aria-label="Investigation priority" value={form.priority} onChange={(event) => setForm({ ...form, priority: event.target.value })}>{["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((value) => <option key={value}>{value}</option>)}</select><textarea aria-label="Investigation summary" placeholder="Summary" value={form.summary} onChange={(event) => setForm({ ...form, summary: event.target.value })} /><textarea aria-label="Investigation notes" placeholder="Notes" value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} /><button className="primary-button" type="submit"><ClipboardPlus size={15} />New investigation</button></form><p className="page-note">{notice}</p><div className="investigation-list">{records.map((record) => <article className="investigation-card" key={record.id}><header><div><SeverityBadge severity={record.priority} /><h3>{record.title}</h3><small>{record.host_ip || "No host selected"} - {record.status}</small></div><button className="icon-button danger-icon" type="button" title={`Delete ${record.title}`} onClick={() => void remove(record.id)}><Trash2 size={14} /></button></header><p>{record.summary || "No summary provided."}</p><footer>{record.notes || "No notes yet."}</footer></article>)}{!records.length && <p className="empty-state">No investigations have been created.</p>}</div></section></div>;
}
