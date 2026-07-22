import { Bot, Languages, LoaderCircle, Sparkles } from "lucide-react";
import { useState } from "react";

import { generateDefenseAdvice } from "../api/llmAdvice";
import type { DefenseAdviceLanguage } from "../api/llmAdvice";
import { useT } from "../i18n/context";
import type { AlertRecord, LlmSettings } from "../types";

interface DefenseAdvicePanelProps {
  alert: AlertRecord;
  settings: LlmSettings;
}

export function DefenseAdvicePanel({ alert, settings }: DefenseAdvicePanelProps) {
  const t = useT();
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
      setError(requestError instanceof Error ? requestError.message : t("defense.failed"));
    } finally {
      setLoading(false);
    }
  };

  return <div className="detail-section defense-advice"><h3>{t("defense.title")}</h3><p>{t("defense.description")}</p><div className="advice-controls"><div className="advice-language" role="group" aria-label={t("defense.response")}><span><Languages size={14} />{t("defense.response")}</span><button type="button" className={language === "en" ? "selected" : ""} aria-pressed={language === "en"} disabled={loading} onClick={() => chooseLanguage("en")}>{t("defense.english")}</button><button type="button" className={language === "zh" ? "selected" : ""} aria-pressed={language === "zh"} disabled={loading} onClick={() => chooseLanguage("zh")}>{t("defense.chinese")}</button></div><button type="button" className="advice-button" onClick={requestAdvice} disabled={loading}>{loading ? <LoaderCircle className="spin" size={15} /> : <Sparkles size={15} />}{loading ? t("defense.generating") : t("defense.generate")}</button></div>{error && <p className="advice-error">{error}</p>}{advice && <div className="advice-output"><Bot size={15} /><pre>{advice}</pre></div>}</div>;
}
