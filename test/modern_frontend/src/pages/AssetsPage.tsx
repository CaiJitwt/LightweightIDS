import { FormEvent, useEffect, useState } from "react";
import { Plus, RefreshCw, Trash2 } from "lucide-react";

import { idsApi } from "../api/idsApi";
import type { AssetRecord } from "../types";

const emptyAsset = { ip: "", displayName: "", role: "Workstation", importance: 50, notes: "" };

export function AssetsPage() {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [form, setForm] = useState(emptyAsset);
  const [notice, setNotice] = useState("Define important assets for host risk prioritization.");
  const load = () => idsApi.assets().then(({ records }) => setAssets(records)).catch(() => setNotice("Local API unavailable. Assets cannot be saved from this preview."));
  useEffect(() => { void load(); }, []);
  const save = async (event: FormEvent) => { event.preventDefault(); try { await idsApi.saveAsset(form); setForm(emptyAsset); setNotice("Asset saved."); await load(); } catch (error) { setNotice(error instanceof Error ? error.message : "Asset could not be saved."); } };
  const remove = async (ip: string) => { await idsApi.deleteAsset(ip); await load(); };
  return <div className="page-stack"><section className="section-panel"><header className="section-heading"><div><h2>Asset inventory</h2><p>Important assets raise analyst priority; they are not allow-list entries.</p></div><button className="icon-button" type="button" title="Refresh assets" onClick={() => void load()}><RefreshCw size={15} /></button></header><form className="asset-form" onSubmit={save}><input required aria-label="Asset IP" placeholder="IP address" value={form.ip} onChange={(event) => setForm({ ...form, ip: event.target.value })} /><input aria-label="Asset name" placeholder="Display name" value={form.displayName} onChange={(event) => setForm({ ...form, displayName: event.target.value })} /><select aria-label="Asset role" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>{["Workstation", "Server", "Database", "Gateway", "Domain Controller", "Other"].map((role) => <option key={role}>{role}</option>)}</select><input aria-label="Asset importance" type="number" min="0" max="100" value={form.importance} onChange={(event) => setForm({ ...form, importance: Number(event.target.value) })} /><input aria-label="Asset notes" placeholder="Notes" value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} /><button className="primary-button" type="submit"><Plus size={15} />Add asset</button></form><p className="page-note">{notice}</p><div className="table-scroll"><table className="data-table"><thead><tr><th>IP</th><th>Name</th><th>Role</th><th>Importance</th><th>Notes</th><th /></tr></thead><tbody>{assets.map((asset) => <tr key={asset.ip}><td>{asset.ip}</td><td>{asset.display_name || "-"}</td><td>{asset.role}</td><td><span className="importance-value">{asset.importance}</span></td><td>{asset.notes || "-"}</td><td><button className="icon-button danger-icon" type="button" title={`Delete ${asset.ip}`} onClick={() => void remove(asset.ip)}><Trash2 size={14} /></button></td></tr>)}</tbody></table></div></section></div>;
}
