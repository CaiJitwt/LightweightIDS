import { FormEvent, useEffect, useMemo, useState } from "react";
import { BarChart3, Package, Pencil, Plus, RefreshCw, Search, Shield, Trash2, X } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import type { AssetRecord } from "../types";

const emptyAsset = { ip: "", displayName: "", role: "Workstation", importance: 50, notes: "" };

export function AssetsPage() {
  const t = useT();
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [query, setQuery] = useState("");
  const [form, setForm] = useState(emptyAsset);
  const [notice, setNotice] = useState("");
  const [saving, setSaving] = useState(false);
  const [editingIp, setEditingIp] = useState<string | null>(null);

  const load = async () => {
    try {
      const { records } = await idsApi.assets();
      setAssets(records);
      setNotice("");
    } catch {
      setNotice(t("assets.unavailable"));
    }
  };
  useEffect(() => { void load(); }, []);

  const visible = useMemo(() => {
    if (!query.trim()) return assets;
    const q = query.toLowerCase();
    return assets.filter((a) => a.ip.toLowerCase().includes(q) || a.display_name.toLowerCase().includes(q) || a.role.toLowerCase().includes(q));
  }, [assets, query]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    try {
      if (editingIp) {
        await idsApi.updateAsset(editingIp, form);
      } else {
        await idsApi.saveAsset(form);
      }
      setForm(emptyAsset);
      setEditingIp(null);
      await load();
      setNotice(editingIp ? t("assets.updated") : t("assets.created"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("assets.saveFailed"));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (ip: string) => {
    try {
      await idsApi.deleteAsset(ip);
      if (editingIp === ip) {
        setEditingIp(null);
        setForm(emptyAsset);
      }
      await load();
      setNotice(t("assets.deleted"));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("assets.deleteFailed"));
    }
  };

  const edit = (asset: AssetRecord) => {
    setEditingIp(asset.ip);
    setForm({ ip: asset.ip, displayName: asset.display_name, role: asset.role, importance: asset.importance, notes: asset.notes });
    setNotice("");
  };

  const cancelEdit = () => {
    setEditingIp(null);
    setForm(emptyAsset);
  };

  const importanceColor = (v: number) => (v >= 80 ? "high" : v >= 50 ? "medium" : "low");
  const highCount = assets.filter((a) => a.importance >= 80).length;
  const roleCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    assets.forEach((a) => { counts[a.role] = (counts[a.role] ?? 0) + 1; });
    return counts;
  }, [assets]);

  return (
    <div className="page-stack asset-workspace">
      <section className="asset-form-panel">
        <header className="section-heading"><div><h2>{editingIp ? t("assets.editAsset") : t("assets.newAsset")}</h2><p>{t("assets.importanceHint")}</p></div><Shield size={17} /></header>
        <form className="asset-form-body" onSubmit={save}>
          <label><span>{t("assets.ipLabel")}</span><input required readOnly={editingIp !== null} placeholder={t("assets.ipPlaceholder")} value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} /></label>
          <label><span>{t("assets.nameLabel")}</span><input placeholder={t("assets.namePlaceholder")} value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></label>
          <label><span>{t("assets.roleLabel")}</span><select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>{["Workstation", "Server", "Database", "Gateway", "Domain Controller", "Other"].map((r) => <option key={r}>{r}</option>)}</select></label>
          <label>
            <span>{t("assets.importanceLabel")} <span className={`importance-val risk-${importanceColor(form.importance)}`}>{form.importance}</span></span>
            <div className="importance-bar-wrap">
              <input type="range" min="0" max="100" value={form.importance} onChange={(e) => setForm({ ...form, importance: Number(e.target.value) })} style={{ flex: 1 }} />
            </div>
          </label>
          <label><span>{t("assets.notesLabel")}</span><textarea placeholder={t("assets.notesPlaceholder")} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} /></label>
          <div className="inline-actions">
            <button className="primary-button" type="submit" disabled={saving}>{editingIp ? <Pencil size={15} /> : <Plus size={15} />}{editingIp ? t("assets.saveChanges") : t("assets.addAsset")}</button>
            {editingIp && <button className="icon-text-button" type="button" onClick={cancelEdit}><X size={15} />{t("common.cancel")}</button>}
          </div>
          {notice && <p className="capture-notice" style={{ margin: 0 }}><Package size={14} />{notice}</p>}
        </form>
      </section>

      <section className="section-panel" style={{ minWidth: 0, display: "flex", flexDirection: "column" }}>
        <header className="section-heading"><div><h2>{t("assets.assetInventory")}</h2><p>{t("assets.assetCount", { count: assets.length, high: highCount })}</p></div><button className="icon-button" type="button" title={t("common.refresh")} onClick={() => void load()}><RefreshCw size={15} /></button></header>

        <div className="filter-row" style={{ borderRadius: 0, borderLeft: 0, borderRight: 0, borderTop: 0 }}>
          <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("assets.search")} /></label>
          <span className="result-count">{visible.length} assets</span>
        </div>

        {Object.keys(roleCounts).length > 0 && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", padding: "8px 14px" }}>
            {Object.entries(roleCounts).map(([role, count]) => (
              <span key={role} style={{ background: "var(--surface-muted)", border: "1px solid var(--border)", borderRadius: 12, padding: "2px 9px", fontSize: 10, color: "var(--muted)", display: "flex", alignItems: "center", gap: 5 }}>
                <BarChart3 size={11} />{role} <strong style={{ color: "var(--text)" }}>{count}</strong>
              </span>
            ))}
          </div>
        )}

        <div className="table-scroll" style={{ flex: 1 }}>
          <table className="data-table">
            <thead><tr><th>{t("assets.ipLabel")}</th><th>{t("assets.nameLabel")}</th><th>{t("assets.roleLabel")}</th><th>{t("assets.importanceLabel")}</th><th>{t("assets.notesLabel")}</th><th /></tr></thead>
            <tbody>
              {visible.length ? visible.map((asset) => (
                <tr key={asset.ip}>
                  <td style={{ fontWeight: 600 }}>{asset.ip}</td>
                  <td>{asset.display_name || "—"}</td>
                  <td>{asset.role}</td>
                  <td>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <span className={`risk-score risk-${importanceColor(asset.importance)}`} style={{ minWidth: 28, fontSize: 10 }}>{asset.importance}</span>
                      <div className="importance-bar" style={{ width: 48 }}>
                        <div className={`importance-bar-fill ${importanceColor(asset.importance)}`} style={{ width: `${asset.importance}%` }} />
                      </div>
                    </span>
                  </td>
                  <td style={{ maxWidth: 160 }}>{asset.notes || "—"}</td>
                  <td><span className="inline-actions"><button className="icon-button" type="button" title={t("common.edit")} onClick={() => edit(asset)} style={{ width: 28, height: 28 }}><Pencil size={13} /></button><button className="icon-button" type="button" title={t("common.delete")} onClick={() => void remove(asset.ip)} style={{ width: 28, height: 28 }}><Trash2 size={13} /></button></span></td>
                </tr>
              )) : <tr><td colSpan={6} className="empty-table">{t("assets.noAssets")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
