import { CheckCircle2, Gauge, KeyRound, MonitorCog, Moon, Save, SlidersHorizontal, Sun, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";

import { idsApi } from "../api/idsApi";
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
    }).catch(() => setRuntimeNotice("Local API unavailable. Detection controls are preview-only."));
  }, [onLlmSettingsChange]);
  const updateRuntime = async (next: Partial<RuntimeSettings>) => {
    setRuntimeSettings((current) => ({ ...current, ...next }));
    try { setRuntimeSettings(await idsApi.saveSettings(next)); setRuntimeNotice("Detection settings saved."); }
    catch { setRuntimeNotice("Local API unavailable. Detection controls are preview-only."); }
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
      setLlmNotice("LLM settings saved securely.");
    } catch (error) {
      setLlmNotice(error instanceof Error ? error.message : "Could not save LLM settings.");
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
      setLlmNotice("Stored API key cleared.");
    } catch (error) {
      setLlmNotice(error instanceof Error ? error.message : "Could not clear the API key.");
    } finally {
      setSavingLlm(false);
    }
  };

  return (
    <div className="page-stack settings-workspace">
      <section className="settings-section">
        <header className="section-heading"><div><h2>Appearance</h2><p>Use a visual mode that stays comfortable during long investigations.</p></div></header>
        <div className="settings-body">
          <div className="setting-row"><div><strong>Theme preference</strong><small>System follows your operating system when it changes.</small></div><div className="theme-segment" role="group" aria-label="Theme preference">
            <button type="button" className={themePreference === "system" ? "selected" : ""} onClick={() => onThemePreferenceChange("system")}><MonitorCog size={15} />System</button>
            <button type="button" className={themePreference === "light" ? "selected" : ""} onClick={() => onThemePreferenceChange("light")}><Sun size={15} />Light</button>
            <button type="button" className={themePreference === "dark" ? "selected" : ""} onClick={() => onThemePreferenceChange("dark")}><Moon size={15} />Dark</button>
          </div></div>
          <div className="setting-row"><div><strong>Font size</strong><small>Applies immediately and is saved to the local project profile.</small></div><div className="theme-segment" role="group" aria-label="Font size">{(["compact", "default", "comfortable"] as FontScale[]).map((value) => <button type="button" key={value} className={fontScale === value ? "selected" : ""} onClick={() => onFontScaleChange(value)}>{value[0].toUpperCase() + value.slice(1)}</button>)}</div></div>
        </div>
      </section>

      <section className="settings-section">
        <header className="section-heading"><div><h2>Detection</h2><p>Shared with new PySide6 capture and import sessions.</p></div><SlidersHorizontal size={17} /></header>
        <div className="settings-body">
          <div className="setting-row"><div><strong>Minimum alert severity</strong><small>Suppresses lower-severity alerts before they are stored.</small></div><select className="plain-select" aria-label="Minimum alert severity" value={runtimeSettings.minimumAlertSeverity} onChange={(event) => void updateRuntime({ minimumAlertSeverity: event.target.value as RuntimeSettings["minimumAlertSeverity"] })}><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>
          <div className="setting-row"><div><strong>Alert cooldown</strong><small>Prevents duplicate alerts for the same rule and communication path.</small></div><label className="number-stepper"><Gauge size={15} /><input aria-label="Alert cooldown seconds" type="number" min="0" max="3600" value={runtimeSettings.alertCooldownSeconds} onChange={(event) => void updateRuntime({ alertCooldownSeconds: Math.max(0, Number(event.target.value) || 0) })} /><span>seconds</span></label></div>
          <Toggle label="Real-time detection" detail="Evaluate enabled rules during live packet capture." checked={runtimeSettings.realtimeDetection} onChange={(value) => void updateRuntime({ realtimeDetection: value })} />
          <Toggle label="Persist packets" detail="Save parsed packet metadata for later investigation and reports." checked={runtimeSettings.autoSavePackets} onChange={(value) => void updateRuntime({ autoSavePackets: value })} />
          <Toggle label="Windows security events" detail="Continuously collect the supported local Windows Event Log channels." checked={runtimeSettings.securityEventMonitorEnabled} onChange={(value) => void updateRuntime({ securityEventMonitorEnabled: value })} />
          <div className="setting-row"><div><strong>Security event interval</strong><small>Polling interval for incremental Windows Event Log collection.</small></div><label className="number-stepper"><Gauge size={15} /><input aria-label="Security event polling seconds" type="number" min="2" max="300" value={runtimeSettings.securityEventPollSeconds} onChange={(event) => void updateRuntime({ securityEventPollSeconds: Math.max(2, Math.min(300, Number(event.target.value) || 5)) })} /><span>seconds</span></label></div>
          <p className="settings-note">{runtimeNotice ? <Save size={14} /> : <CheckCircle2 size={14} />}{runtimeNotice || "Changes apply to new capture or import sessions."}</p>
        </div>
      </section>

      <section className="settings-section">
        <header className="section-heading"><div><h2>LLM defense guidance</h2><p>Configure an OpenAI-compatible endpoint for analyst-requested recommendations.</p></div><span className="local-only"><KeyRound size={14} />Protected locally</span></header>
        <div className="settings-body llm-settings">
          <label><span>Base URL</span><input value={llmForm.baseUrl} onChange={(event) => setLlmForm((current) => ({ ...current, baseUrl: event.target.value }))} placeholder="https://api.example.com/v1" autoComplete="url" /></label>
          <label><span>Model</span><input value={llmForm.model} onChange={(event) => setLlmForm((current) => ({ ...current, model: event.target.value }))} placeholder="gpt-4.1-mini" autoComplete="off" /></label>
          <label className="api-key-field"><span>API key</span><input type="password" value={apiKeyDraft} onChange={(event) => setApiKeyDraft(event.target.value)} placeholder={runtimeSettings.llmApiKeyConfigured ? "API key configured - enter a new key to replace it" : "Enter API key"} autoComplete="new-password" /></label>
          <div className="llm-actions"><button type="button" className="icon-text-button primary" disabled={savingLlm} onClick={() => void saveLlmSettings()}><Save size={15} />{savingLlm ? "Saving" : "Save LLM settings"}</button>{runtimeSettings.llmApiKeyConfigured && <button type="button" className="icon-text-button" disabled={savingLlm} onClick={() => void clearApiKey()}><Trash2 size={15} />Clear API key</button>}</div>
          <p className="settings-note"><KeyRound size={14} />{llmNotice || "The API key is encrypted for your Windows account and is never returned to the browser. Alert data is sent only after you select Generate defense guidance."}</p>
        </div>
      </section>
    </div>
  );
}

function Toggle({ label, detail, checked, onChange }: { label: string; detail: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <div className="setting-row"><div><strong>{label}</strong><small>{detail}</small></div><label className="switch"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span /></label></div>;
}
