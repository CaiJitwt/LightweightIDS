import { useEffect, useState } from "react";
import { Info, RefreshCw, ShieldCheck } from "lucide-react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import { SeverityBadge } from "../components/SeverityBadge";
import { FALLBACK_RULE_GUIDANCE, RULE_GUIDANCE } from "../data/ruleGuidance";
import type { RuleRecord } from "../types";

export function RulesPage() {
  const t = useT();
  const [records, setRecords] = useState<RuleRecord[]>([]);
  const [notice, setNotice] = useState(t("rules.defaultNotice"));
  const load = () => idsApi.rules().then(({ records: next }) => { setRecords(next); setNotice(t("rules.loaded", { count: next.length })); }).catch(() => setNotice(t("rules.unavailable")));
  useEffect(() => { void load(); }, []);
  const update = async (rule: RuleRecord, changes: Partial<Pick<RuleRecord, "enabled" | "threshold" | "timeWindow">>) => {
    try {
      const { record } = await idsApi.updateRule(rule.id, changes);
      setRecords((items) => items.map((item) => item.id === rule.id ? record : item));
      setNotice(t("rules.updated", { name: record.name }));
    } catch (error) { setNotice(error instanceof Error ? error.message : t("rules.updateFailed")); }
  };
  return (
    <div className="page-stack">
      <section className="section-panel">
        <header className="section-heading">
          <div><h2>{t("rules.title")}</h2><p>{t("rules.subtitle")}</p></div>
          <button className="icon-button" type="button" title={t("rules.refresh")} onClick={() => void load()}><RefreshCw size={15} /></button>
        </header>
        <p className="page-note"><ShieldCheck size={15} />{notice}</p>
        <div className="rule-tuning-note">
          <Info size={16} />
          <div><strong>{t("rules.tuningTitle")}</strong><p>{t("rules.tuningBody")}</p></div>
        </div>
        <div className="table-scroll">
          <table className="data-table rules-table">
            <thead><tr><th>{t("rules.columnRule")}</th><th>{t("rules.columnSeverity")}</th><th>{t("rules.columnEnabled")}</th><th title={t("rules.thresholdTitle")}>{t("rules.columnThreshold")}</th><th title={t("rules.windowTitle")}>{t("rules.columnWindow")}</th><th>{t("rules.columnTuning")}</th><th>{t("rules.columnDescription")}</th></tr></thead>
            <tbody>
              {records.map((rule) => {
                const guidance = RULE_GUIDANCE[rule.id] ?? FALLBACK_RULE_GUIDANCE;
                const resourceLoadRule = rule.id === "SUSTAINED_CPU_LOAD" || rule.id === "SUSTAINED_GPU_LOAD";
                return <tr key={rule.id}>
                  <td><div className="rule-identity"><strong>{rule.name}</strong><span className="rule-category" data-category={rule.category}>{rule.category}</span></div></td>
                  <td><SeverityBadge severity={rule.severity} /></td>
                  <td><label className="switch"><input aria-label={t("rules.columnEnabled")} type="checkbox" checked={rule.enabled} onChange={(event) => void update(rule, { enabled: event.target.checked })} /><span /></label></td>
                  <td><input className="table-input" aria-label={t("rules.columnThreshold")} type="number" min="1" max={resourceLoadRule ? 100 : undefined} value={rule.threshold} onChange={(event) => void update(rule, { threshold: resourceLoadRule ? Math.max(1, Math.min(100, Number(event.target.value) || 1)) : Math.max(1, Number(event.target.value) || 1) })} /></td>
                  <td><input className="table-input" aria-label={t("rules.columnWindow")} type="number" min="0" value={rule.timeWindow} onChange={(event) => void update(rule, { timeWindow: Math.max(0, Number(event.target.value) || 0) })} /></td>
                  <td className="rule-guidance-cell">
                    <p><strong>{t("rules.method")}</strong>{guidance.method}</p>
                    <p><strong>{t("rules.thresholdGuide")}</strong>{guidance.threshold}</p>
                    <p><strong>{t("rules.windowGuide")}</strong>{guidance.window}</p>
                  </td>
                  <td title={rule.description}>{rule.description}</td>
                </tr>;
              })}
              {!records.length && <tr><td colSpan={7} className="empty-table">{t("rules.noData")}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
