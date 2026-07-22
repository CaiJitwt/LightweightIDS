import { CheckCircle2, Gauge, KeyRound, MonitorCog, Moon, Save, SlidersHorizontal, Sun, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { idsApi } from "../api/idsApi";
import { useT } from "../i18n/context";
import type { FontScale, LlmSettings, RuntimeSettings, ThemePreference } from "../types";

const fallbackSettings: RuntimeSettings = { themePreference: "system", fontScale: "default", autoSavePackets: true, realtimeDetection: true, alertCooldownSeconds: 10, minimumAlertSeverity: "LOW", securityEventMonitorEnabled: false, securityEventPollSeconds: 5, llmBaseUrl: "https://api.openai.com/v1", llmModel: "gpt-4.1-mini", llmApiKeyConfigured: false };

interface SettingsPageProps {
  themePreference: ThemePreference;
  onThemePreferenceChange: (value: ThemePreference) => void;
  fontScale: FontScale;
  onFontScaleChange: (value: FontScale) => void;
  llmSettings: LlmSettings;
  onLlmSettingsChange: (settings: LlmSettings) => void;
}

export function SettingsPage({ themePreference, onThemePreferenceChange, fontScale, onFontScaleChange, llmSettings, onLlmSettingsChange }: SettingsPageProps) {
  const t = useT();
  const [runtimeSettings, setRuntimeSettings] = useState(fallbackSettings);
  const [runtimeNotice, setRuntimeNotice] = useState("");
  const [llmForm, setLlmForm] = useState(() => ({ baseUrl: llmSettings.baseUrl, model: llmSettings.model }));
  const [apiKeyDraft, setApiKeyDraft] = useState("");
  const [llmNotice, setLlmNotice] = useState("");
  const [savingLlm, setSavingLlm] = useState(false);

  useEffect(() => {
    idsApi.settings().then((settings) => {
      setRuntimeSettings(settings);
      setLlmForm({ baseUrl: settings.llmBaseUrl, model: settings.llmModel });
      onLlmSettingsChange({ baseUrl: settings.llmBaseUrl, model: settings.llmModel, apiKeyConfigured: settings.llmApiKeyConfigured });
    }).catch(() => setRuntimeNotice(t("settings.unavailable")));
  }, [onLlmSettingsChange, t]);
  const updateRuntime = async (next: Partial<RuntimeSettings>) => {
    setRuntimeSettings((current) => ({ ...current, ...next }));
    try { setRuntimeSettings(await idsApi.saveSettings(next)); setRuntimeNotice(t("settings.saved")); }
    catch { setRuntimeNotice(t("settings.unavailable")); }
  };
  const saveLlmSettings = async () => {
    setSavingLlm(true);
    setLlmNotice("");
    try {
      const saved = await idsApi.saveSettings({
        llmBaseUrl: llmForm.baseUrl,
        llmModel: llmForm.model,
        ...(apiKeyDraft.trim() ? { llmApiKey: apiKeyDraft.trim() } : {}),
      });
      setRuntimeSettings(saved);
      setApiKeyDraft("");
      setLlmForm({ baseUrl: saved.llmBaseUrl, model: saved.llmModel });
      onLlmSettingsChange({ baseUrl: saved.llmBaseUrl, model: saved.llmModel, apiKeyConfigured: saved.llmApiKeyConfigured });
      setLlmNotice(t("settings.llmSaved"));
    } catch (error) {
      setLlmNotice(error instanceof Error ? error.message : t("settings.llmSaveFailed"));
    } finally {
      setSavingLlm(false);
    }
  };
  const clearApiKey = async () => {
    setSavingLlm(true);
    setLlmNotice("");
    try {
      const saved = await idsApi.saveSettings({ clearLlmApiKey: true });
      setRuntimeSettings(saved);
      setApiKeyDraft("");
      onLlmSettingsChange({ baseUrl: saved.llmBaseUrl, model: saved.llmModel, apiKeyConfigured: false });
      setLlmNotice(t("settings.apiKeyCleared"));
    } catch (error) {
      setLlmNotice(error instanceof Error ? error.message : t("settings.apiKeyClearFailed"));
    } finally {
      setSavingLlm(false);
    }
  };

  return (
    <div className="page-stack settings-workspace">
      <section className="settings-section">
        <header className="section-heading"><div><h2>{t("settings.appearance")}</h2><p>{t("settings.appearanceMeta")}</p></div></header>
        <div className="settings-body">
          <div className="setting-row"><div><strong>{t("settings.themePref")}</strong><small>{t("settings.themePrefMeta")}</small></div><div className="theme-segment" role="group" aria-label={t("settings.themePref")}>
            <button type="button" className={themePreference === "system" ? "selected" : ""} onClick={() => onThemePreferenceChange("system")}><MonitorCog size={15} />System</button>
            <button type="button" className={themePreference === "light" ? "selected" : ""} onClick={() => onThemePreferenceChange("light")}><Sun size={15} />Light</button>
            <button type="button" className={themePreference === "dark" ? "selected" : ""} onClick={() => onThemePreferenceChange("dark")}><Moon size={15} />Dark</button>
          </div></div>
          <div className="setting-row"><div><strong>{t("settings.fontSize")}</strong><small>{t("settings.fontSizeMeta")}</small></div><div className="theme-segment" role="group" aria-label={t("settings.fontSize")}>{(["compact", "default", "comfortable"] as FontScale[]).map((value) => <button type="button" key={value} className={fontScale === value ? "selected" : ""} onClick={() => onFontScaleChange(value)}>{value[0].toUpperCase() + value.slice(1)}</button>)}</div></div>
        </div>
      </section>

      <section className="settings-section">
        <header className="section-heading"><div><h2>{t("settings.detection")}</h2><p>{t("settings.detectionMeta")}</p></div><SlidersHorizontal size={17} /></header>
        <div className="settings-body">
          <div className="setting-row"><div><strong>{t("settings.minSeverity")}</strong><small>{t("settings.minSeverityMeta")}</small></div><select className="plain-select" aria-label={t("settings.minSeverity")} value={runtimeSettings.minimumAlertSeverity} onChange={(event) => void updateRuntime({ minimumAlertSeverity: event.target.value as RuntimeSettings["minimumAlertSeverity"] })}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>
          <div className="setting-row"><div><strong>{t("settings.alertCooldown")}</strong><small>{t("settings.alertCooldownMeta")}</small></div><label className="number-stepper"><Gauge size={15} /><input aria-label={t("settings.alertCooldown")} type="number" min="0" max="3600" value={runtimeSettings.alertCooldownSeconds} onChange={(event) => void updateRuntime({ alertCooldownSeconds: Math.max(0, Number(event.target.value) || 0) })} /><span>{t("settings.seconds")}</span></label></div>
          <Toggle label={t("settings.realtimeDetection")} detail={t("settings.realtimeDetectionMeta")} checked={runtimeSettings.realtimeDetection} onChange={(value) => void updateRuntime({ realtimeDetection: value })} />
          <Toggle label={t("settings.persistPackets")} detail={t("settings.persistPacketsMeta")} checked={runtimeSettings.autoSavePackets} onChange={(value) => void updateRuntime({ autoSavePackets: value })} />
          <Toggle label={t("settings.winSecurityEvents")} detail={t("settings.winSecurityEventsMeta")} checked={runtimeSettings.securityEventMonitorEnabled} onChange={(value) => void updateRuntime({ securityEventMonitorEnabled: value })} />
          <div className="setting-row"><div><strong>{t("settings.securityEventInterval")}</strong><small>{t("settings.securityEventIntervalMeta")}</small></div><label className="number-stepper"><Gauge size={15} /><input aria-label={t("settings.securityEventInterval")} type="number" min="2" max="300" value={runtimeSettings.securityEventPollSeconds} onChange={(event) => void updateRuntime({ securityEventPollSeconds: Math.max(2, Math.min(300, Number(event.target.value) || 5)) })} /><span>{t("settings.seconds")}</span></label></div>
          <p className="settings-note">{runtimeNotice ? <Save size={14} /> : <CheckCircle2 size={14} />}{runtimeNotice || t("settings.applyNote")}</p>
        </div>
      </section>

      <section className="settings-section">
        <header className="section-heading"><div><h2>{t("settings.llmTitle")}</h2><p>{t("settings.llmMeta")}</p></div><span className="local-only"><KeyRound size={14} />{t("settings.protectedLocally")}</span></header>
        <div className="settings-body llm-settings">
          <label><span>{t("settings.baseUrl")}</span><input value={llmForm.baseUrl} onChange={(event) => setLlmForm((current) => ({ ...current, baseUrl: event.target.value }))} placeholder="https://api.example.com/v1" autoComplete="url" /></label>
          <label><span>{t("settings.model")}</span><input value={llmForm.model} onChange={(event) => setLlmForm((current) => ({ ...current, model: event.target.value }))} placeholder="gpt-4.1-mini" autoComplete="off" /></label>
          <label className="api-key-field"><span>{t("settings.apiKey")}</span><input type="password" value={apiKeyDraft} onChange={(event) => setApiKeyDraft(event.target.value)} placeholder={runtimeSettings.llmApiKeyConfigured ? t("settings.apiKeyConfigured") : t("settings.apiKeyPlaceholder")} autoComplete="new-password" /></label>
          <div className="llm-actions"><button type="button" className="icon-text-button primary" disabled={savingLlm} onClick={() => void saveLlmSettings()}><Save size={15} />{savingLlm ? t("settings.saving") : t("settings.saveLlm")}</button>{runtimeSettings.llmApiKeyConfigured && <button type="button" className="icon-text-button" disabled={savingLlm} onClick={() => void clearApiKey()}><Trash2 size={15} />{t("settings.clearApiKey")}</button>}</div>
          <p className="settings-note"><KeyRound size={14} />{llmNotice || t("settings.llmNote")}</p>
        </div>
      </section>
    </div>
  );
}

function Toggle({ label, detail, checked, onChange }: { label: string; detail: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <div className="setting-row"><div><strong>{label}</strong><small>{detail}</small></div><label className="switch"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span /></label></div>;
}
