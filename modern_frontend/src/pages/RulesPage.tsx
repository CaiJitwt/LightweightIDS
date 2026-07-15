import { useEffect, useState } from "react";
import { Info, RefreshCw, ShieldCheck } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { SeverityBadge } from "../components/SeverityBadge";
import { FALLBACK_RULE_GUIDANCE, RULE_GUIDANCE } from "../data/ruleGuidance";
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
  return (
    <div className="page-stack">
      <section className="section-panel">
        <header className="section-heading">
          <div><h2>Built-in detection rules</h2><p>Thresholds and windows apply to future detection sessions</p></div>
          <button className="icon-button" type="button" title="Refresh rules" onClick={() => void load()}><RefreshCw size={15} /></button>
        </header>
        <p className="page-note"><ShieldCheck size={15} />{notice}</p>
        <div className="rule-tuning-note">
          <Info size={16} />
          <div><strong>Rule tuning reference</strong><p>Threshold controls the count, multiplier or score needed to alert. Window is measured in seconds; 0 means immediate packet evaluation without time aggregation.</p></div>
        </div>
        <div className="table-scroll">
          <table className="data-table rules-table">
            <thead><tr><th>Rule</th><th>Severity</th><th>Enabled</th><th title="Rule-specific count, multiplier or score">Threshold</th><th title="Observation period in seconds">Window</th><th>Detection and tuning</th><th>Description</th></tr></thead>
            <tbody>
              {records.map((rule) => {
                const guidance = RULE_GUIDANCE[rule.id] ?? FALLBACK_RULE_GUIDANCE;
                const resourceLoadRule = rule.id === "SUSTAINED_CPU_LOAD" || rule.id === "SUSTAINED_GPU_LOAD";
                return <tr key={rule.id}>
                  <td><div className="rule-identity"><strong>{rule.name}</strong><span className="rule-category" data-category={rule.category}>{rule.category}</span></div></td>
                  <td><SeverityBadge severity={rule.severity} /></td>
                  <td><label className="switch"><input aria-label={`Enable ${rule.name}`} type="checkbox" checked={rule.enabled} onChange={(event) => void update(rule, { enabled: event.target.checked })} /><span /></label></td>
                  <td><input className="table-input" aria-label={`${rule.name} threshold`} type="number" min="1" max={resourceLoadRule ? 100 : undefined} value={rule.threshold} onChange={(event) => void update(rule, { threshold: resourceLoadRule ? Math.max(1, Math.min(100, Number(event.target.value) || 1)) : Math.max(1, Number(event.target.value) || 1) })} /></td>
                  <td><input className="table-input" aria-label={`${rule.name} window`} type="number" min="0" value={rule.timeWindow} onChange={(event) => void update(rule, { timeWindow: Math.max(0, Number(event.target.value) || 0) })} /></td>
                  <td className="rule-guidance-cell">
                    <p><strong>Method</strong>{guidance.method}</p>
                    <p><strong>Threshold</strong>{guidance.threshold}</p>
                    <p><strong>Window</strong>{guidance.window}</p>
                  </td>
                  <td title={rule.description}>{rule.description}</td>
                </tr>;
              })}
              {!records.length && <tr><td colSpan={7} className="empty-table">No rule data is available.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
