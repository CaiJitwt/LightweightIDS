import { useEffect, useState } from "react";
import { Check, RefreshCw, ShieldCheck } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import type { RuleRecord } from "../types";

export function RulesPage() {
  const [records, setRecords] = useState<RuleRecord[]>([]);
  const [notice, setNotice] = useState("Start the local API to manage persisted rule settings.");
  const load = () => idsApi.rules().then(({ records: next }) => { setRecords(next); setNotice(`${next.length} built-in rules loaded.`); }).catch(() => setNotice("Local API unavailable. Rule edits are disabled."));
  useEffect(() => { void load(); }, []);
  const update = async (rule: RuleRecord, changes: Partial<Pick<RuleRecord, "enabled" | "threshold" | "timeWindow">>) => {
    try {
      const { record } = await idsApi.updateRule(rule.id, changes);
      setRecords((items) => items.map((item) => item.id === rule.id ? record : item));
      setNotice(`${record.name} updated.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not update rule."); }
  };
  return <div className="page-stack"><section className="section-panel"><header className="section-heading"><div><h2>Built-in detection rules</h2><p>Thresholds and windows apply to future detection sessions</p></div><button className="icon-button" type="button" title="Refresh rules" onClick={() => void load()}><RefreshCw size={15} /></button></header><p className="page-note"><ShieldCheck size={15} />{notice}</p><div className="table-scroll"><table className="data-table rules-table"><thead><tr><th>Rule</th><th>Severity</th><th>Enabled</th><th>Threshold</th><th>Window</th><th>Description</th></tr></thead><tbody>{records.map((rule) => <tr key={rule.id}><td><strong>{rule.name}</strong><small>{rule.category}</small></td><td><SeverityBadge severity={rule.severity} /></td><td><label className="switch"><input aria-label={`Enable ${rule.name}`} type="checkbox" checked={rule.enabled} onChange={(event) => void update(rule, { enabled: event.target.checked })} /><span /></label></td><td><input className="table-input" aria-label={`${rule.name} threshold`} type="number" min="0" value={rule.threshold} onChange={(event) => void update(rule, { threshold: Number(event.target.value) || 0 })} /></td><td><input className="table-input" aria-label={`${rule.name} window`} type="number" min="0" value={rule.timeWindow} onChange={(event) => void update(rule, { timeWindow: Number(event.target.value) || 0 })} /></td><td title={rule.description}>{rule.description}</td></tr>)}{!records.length && <tr><td colSpan={6} className="empty-table">No rule data is available.</td></tr>}</tbody></table></div></section></div>;
}
