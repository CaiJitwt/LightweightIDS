import { CheckCircle2, Eye, EyeOff, Gauge, KeyRound, MonitorCog, Moon, Save, SlidersHorizontal, Sun } from "lucide-react";
import { useEffect, useState } from "react";

import { idsApi } from "../api/idsApi";
import type { FontScale, LlmSettings, RuntimeSettings, ThemePreference } from "../types";

const fallbackSettings: RuntimeSettings = { autoSavePackets: true, realtimeDetection: true, alertCooldownSeconds: 10, minimumAlertSeverity: "LOW", securityEventMonitorEnabled: false, securityEventPollSeconds: 5 };

interface SettingsPageProps {
  themePreference: ThemePreference;
  onThemePreferenceChange: (value: ThemePreference) => void;
  fontScale: FontScale;
  onFontScaleChange: (value: FontScale) => void;
  llmSettings: LlmSettings;
  onLlmSettingsChange: (settings: LlmSettings) => void;
}

export function SettingsPage({ themePreference, onThemePreferenceChange, fontScale, onFontScaleChange, llmSettings, onLlmSettingsChange }: SettingsPageProps) {
  const [showKey, setShowKey] = useState(false);
  const [runtimeSettings, setRuntimeSettings] = useState(fallbackSettings);
  const [runtimeNotice, setRuntimeNotice] = useState("");
  const update = (field: keyof LlmSettings, value: string) => onLlmSettingsChange({ ...llmSettings, [field]: value });

  useEffect(() => { idsApi.settings().then(setRuntimeSettings).catch(() => setRuntimeNotice("Local API unavailable. Detection controls are preview-only.")); }, []);
  const updateRuntime = async (next: Partial<RuntimeSettings>) => {
    setRuntimeSettings((current) => ({ ...current, ...next }));
    try { setRuntimeSettings(await idsApi.saveSettings(next)); setRuntimeNotice("Detection settings saved."); }
    catch { setRuntimeNotice("Local API unavailable. Detection controls are preview-only."); }
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
          <div className="setting-row"><div><strong>Font size</strong><small>Applies immediately and is remembered in this browser.</small></div><div className="theme-segment" role="group" aria-label="Font size">{(["compact", "default", "comfortable"] as FontScale[]).map((value) => <button type="button" key={value} className={fontScale === value ? "selected" : ""} onClick={() => onFontScaleChange(value)}>{value[0].toUpperCase() + value.slice(1)}</button>)}</div></div>
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
        <header className="section-heading"><div><h2>LLM defense guidance</h2><p>Configure an OpenAI-compatible endpoint for analyst-requested recommendations.</p></div><span className="local-only"><KeyRound size={14} />Local session</span></header>
        <div className="settings-body llm-settings">
          <label><span>Base URL</span><input value={llmSettings.baseUrl} onChange={(event) => update("baseUrl", event.target.value)} placeholder="https://api.example.com/v1" autoComplete="url" /></label>
          <label><span>Model</span><input value={llmSettings.model} onChange={(event) => update("model", event.target.value)} placeholder="gpt-4.1-mini" autoComplete="off" /></label>
          <label className="api-key-field"><span>API key</span><div><input type={showKey ? "text" : "password"} value={llmSettings.apiKey} onChange={(event) => update("apiKey", event.target.value)} placeholder="Stored only for this browser session" autoComplete="off" /><button type="button" className="icon-button" title={showKey ? "Hide API key" : "Show API key"} onClick={() => setShowKey((value) => !value)}>{showKey ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
          <p className="settings-note"><Save size={14} />Base URL, model, and theme preference are saved locally. The API key remains in browser session storage and alert data is sent only after you select Generate defense guidance.</p>
        </div>
      </section>
    </div>
  );
}

function Toggle({ label, detail, checked, onChange }: { label: string; detail: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <div className="setting-row"><div><strong>{label}</strong><small>{detail}</small></div><label className="switch"><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span /></label></div>;
}
