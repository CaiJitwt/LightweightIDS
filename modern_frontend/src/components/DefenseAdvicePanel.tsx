import { Bot, LoaderCircle, Sparkles } from "lucide-react";
import { useState } from "react";

import { generateDefenseAdvice } from "../api/llmAdvice";
import type { AlertRecord, LlmSettings } from "../types";

interface DefenseAdvicePanelProps {
  alert: AlertRecord;
  settings: LlmSettings;
}

export function DefenseAdvicePanel({ alert, settings }: DefenseAdvicePanelProps) {
  const [advice, setAdvice] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const requestAdvice = async () => {
    setLoading(true);
    setError("");
    try {
      setAdvice(await generateDefenseAdvice(settings, alert));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not generate defense guidance.");
    } finally {
      setLoading(false);
    }
  };

  return <div className="detail-section defense-advice"><h3>Defense guidance</h3><p>Send this alert's metadata and evidence to the configured LLM endpoint.</p><button type="button" className="advice-button" onClick={requestAdvice} disabled={loading}>{loading ? <LoaderCircle className="spin" size={15} /> : <Sparkles size={15} />}{loading ? "Generating guidance" : "Generate defense guidance"}</button>{error && <p className="advice-error">{error}</p>}{advice && <div className="advice-output"><Bot size={15} /><pre>{advice}</pre></div>}</div>;
}
