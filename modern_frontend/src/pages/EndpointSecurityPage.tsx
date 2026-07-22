import { FileCheck2, Folder, RefreshCw, ScanSearch, ShieldCheck, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import type { IntegrityResult, IntegrityStatus, ProcessRecord, SecurityCheck } from "../types";

const emptyIntegrity: IntegrityStatus = { available: false, paths: [], fileCount: 0, createdAt: "" };

export function EndpointSecurityPage({ refreshVersion }: { refreshVersion: number }) {
  const t = useT();
  const [checks, setChecks] = useState<SecurityCheck[]>([]);
  const [processes, setProcesses] = useState<ProcessRecord[]>([]);
  const [integrity, setIntegrity] = useState<IntegrityStatus>(emptyIntegrity);
  const [paths, setPaths] = useState("");
  const [result, setResult] = useState<IntegrityResult | null>(null);
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setNotice("");
    const [posture, processResponse, integrityStatus] = await Promise.allSettled([idsApi.posture(), idsApi.processes(), idsApi.integrityStatus()]);
    const failures: string[] = [];
    if (posture.status === "fulfilled") setChecks(posture.value.checks);
    else { setChecks([]); failures.push(`Posture: ${errorMessage(posture.reason)}`); }
    if (processResponse.status === "fulfilled") setProcesses(processResponse.value.processes);
    else { setProcesses([]); failures.push(`Processes: ${errorMessage(processResponse.reason)}`); }
    if (integrityStatus.status === "fulfilled") {
      setIntegrity(integrityStatus.value);
      if (integrityStatus.value.paths.length) setPaths(integrityStatus.value.paths.join("\n"));
    } else {
      setIntegrity(emptyIntegrity);
      failures.push(`File integrity: ${errorMessage(integrityStatus.reason)}`);
    }
    setNotice(failures.join(" "));
    setLoading(false);
  }, []);

  useEffect(() => { void load(); }, [load, refreshVersion]);

  const createBaseline = async () => {
    const selectedPaths = paths.split(/[\n;]/).map((path) => path.trim()).filter(Boolean);
    setLoading(true);
    setNotice("");
    try {
      const baseline = await idsApi.createIntegrityBaseline(selectedPaths);
      setResult(baseline);
      setIntegrity({ available: true, paths: baseline.paths, fileCount: baseline.fileCount, createdAt: baseline.createdAt ?? "" });
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("endpoint.baselineFailed"));
    } finally {
      setLoading(false);
    }
  };

  const scan = async () => {
    setLoading(true);
    setNotice("");
    try {
      setResult(await idsApi.scanIntegrity());
    } catch (error) {
      setNotice(error instanceof Error ? error.message : t("endpoint.scanFailed"));
    } finally {
      setLoading(false);
    }
  };

  const passCount = checks.filter((check) => check.state === "pass").length;
  return <div className="page-stack endpoint-workspace" data-refresh-version={refreshVersion}>
    <section className="endpoint-toolbar"><div><ShieldCheck size={18} /><span><strong>{t("endpoint.posture")}</strong><small>{t("endpoint.postureMeta")}</small></span></div><button className="icon-text-button" type="button" onClick={() => void load()} disabled={loading}><RefreshCw className={loading ? "spin" : ""} size={16} />{t("endpoint.refreshChecks")}</button></section>
    {notice && <p className="capture-notice error"><TriangleAlert size={15} />{notice}</p>}
    <section className="posture-grid">{checks.length ? checks.map((check) => <article className={`posture-card posture-${check.state}`} key={check.identifier}><header><span className={`posture-dot ${check.state}`} /><strong>{check.title}</strong><small>{check.value}</small></header><p>{check.detail}</p><footer>{check.recommendation}</footer></article>) : <div className="empty-security">{t("endpoint.noChecks")}</div>}</section>
    <section className="endpoint-summary"><div><span>{t("endpoint.passingChecks")}</span><strong>{passCount}/{checks.length || 0}</strong></div><div><span>{t("endpoint.observedProcesses")}</span><strong>{processes.length}</strong></div><div><span>{t("endpoint.integrityBaseline")}</span><strong>{integrity.available ? t("endpoint.filesCount", { count: integrity.fileCount }) : t("endpoint.notCreated")}</strong></div></section>
    <section className="endpoint-lower">
      <article className="integrity-panel"><header className="section-heading"><div><h2>{t("endpoint.fileIntegrity")}</h2><p>{t("endpoint.integrityMeta")}</p></div><FileCheck2 size={17} /></header><div className="integrity-body"><label><span>{t("endpoint.dirsOrFiles")}</span><textarea value={paths} onChange={(event) => setPaths(event.target.value)} placeholder={"C:\\Users\\Analyst\\Documents\\Project\nC:\\Security\\config.json"} /></label><div className="integrity-actions"><button className="primary-button" type="button" onClick={() => void createBaseline()} disabled={loading}><Folder size={15} />{t("endpoint.createBaseline")}</button><button className="icon-text-button" type="button" onClick={() => void scan()} disabled={loading || !integrity.available}><ScanSearch size={15} />{t("endpoint.scanChanges")}</button></div>{result && <div className="integrity-result"><strong>{result.scannedAt ? t("endpoint.scanComplete") : t("endpoint.baselineCreated")}</strong><span>{t("endpoint.integrityResult", { files: result.fileCount, added: result.added?.length ?? 0, modified: result.modified?.length ?? 0, removed: result.removed?.length ?? 0, skipped: result.skipped.length })}</span></div>}</div></article>
      <article className="process-panel"><header className="section-heading"><div><h2>{t("endpoint.processInventory")}</h2><p>{t("endpoint.processMeta")}</p></div></header><div className="process-list">{processes.slice(0, 12).map((process) => <div key={process.pid}><span><strong>{process.name}</strong><small>PID {process.pid}{process.memory ? ` - ${process.memory}` : ""}</small></span><code>{process.path || t("endpoint.pathUnavailable")}</code></div>)}{!processes.length && <p>{t("endpoint.noProcesses")}</p>}</div></article>
    </section>
  </div>;
}

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "Local collection unavailable.";
}
