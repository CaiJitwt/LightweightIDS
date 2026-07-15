import { Bot, Languages, LoaderCircle, Sparkles } from "lucide-react";
import { useState } from "react";

import { generateDefenseAdvice } from "../api/llmAdvice";
import type { DefenseAdviceLanguage } from "../api/llmAdvice";
import type { AlertRecord, LlmSettings } from "../types";

interface DefenseAdvicePanelProps {
  alert: AlertRecord;
  settings: LlmSettings;
}

export function DefenseAdvicePanel({ alert, settings }: DefenseAdvicePanelProps) {
  const [advice, setAdvice] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [language, setLanguage] = useState<DefenseAdviceLanguage>("en");

  const chooseLanguage = (nextLanguage: DefenseAdviceLanguage) => {
    setLanguage(nextLanguage);
    setAdvice("");
    setError("");
  };

  const requestAdvice = async () => {
    setLoading(true);
    setError("");
    try {
      setAdvice(await generateDefenseAdvice(settings, alert, language));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not generate defense guidance.");
    } finally {
      setLoading(false);
    }
  };

  return <div className="detail-section defense-advice"><h3>Defense guidance</h3><p>Send this alert's metadata and evidence to the configured LLM endpoint.</p><div className="advice-controls"><div className="advice-language" role="group" aria-label="Response language"><span><Languages size={14} />Response</span><button type="button" className={language === "en" ? "selected" : ""} aria-pressed={language === "en"} disabled={loading} onClick={() => chooseLanguage("en")}>English</button><button type="button" className={language === "zh" ? "selected" : ""} aria-pressed={language === "zh"} disabled={loading} onClick={() => chooseLanguage("zh")}>Chinese</button></div><button type="button" className="advice-button" onClick={requestAdvice} disabled={loading}>{loading ? <LoaderCircle className="spin" size={15} /> : <Sparkles size={15} />}{loading ? "Generating guidance" : "Generate defense guidance"}</button></div>{error && <p className="advice-error">{error}</p>}{advice && <div className="advice-output"><Bot size={15} /><pre>{advice}</pre></div>}</div>;
}
