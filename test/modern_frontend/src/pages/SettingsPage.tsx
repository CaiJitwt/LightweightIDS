import { Eye, EyeOff, KeyRound, MonitorCog, Moon, Save, Sun } from "lucide-react";
import { useState } from "react";

import type { LlmSettings, ThemePreference } from "../types";

interface SettingsPageProps {
  themePreference: ThemePreference;
  onThemePreferenceChange: (value: ThemePreference) => void;
  llmSettings: LlmSettings;
  onLlmSettingsChange: (settings: LlmSettings) => void;
}

export function SettingsPage({ themePreference, onThemePreferenceChange, llmSettings, onLlmSettingsChange }: SettingsPageProps) {
  const [showKey, setShowKey] = useState(false);
  const update = (field: keyof LlmSettings, value: string) => onLlmSettingsChange({ ...llmSettings, [field]: value });

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
