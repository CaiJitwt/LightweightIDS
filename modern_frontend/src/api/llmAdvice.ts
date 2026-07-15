import type { AlertRecord, LlmSettings } from "../types";

export type DefenseAdviceLanguage = "en" | "zh";

export async function generateDefenseAdvice(settings: LlmSettings, alert: AlertRecord, language: DefenseAdviceLanguage): Promise<string> {
  if (!settings.baseUrl.trim() || !settings.model.trim() || !settings.apiKeyConfigured) {
    throw new Error("Save a Base URL, API key, and model in Settings before requesting guidance.");
  }
  const response = await fetch("/api/llm/defense-guidance", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      language,
      alert: {
        rule: alert.ruleName,
        ruleId: alert.ruleId,
        severity: alert.severity,
        source: alert.source,
        destination: alert.destination,
        protocol: alert.protocol,
        description: alert.description,
        evidence: alert.evidence,
        status: alert.status,
      },
    }),
  });
  const body = await response.json().catch(() => ({})) as { guidance?: string; error?: string };
  if (!response.ok) throw new Error(body.error ?? `LLM request failed (${response.status}).`);
  if (!body.guidance?.trim()) throw new Error("The LLM response did not contain guidance.");
  return body.guidance;
}
