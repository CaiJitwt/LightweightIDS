import { createContext, useCallback, useContext } from "react";
import type { Locale, TranslationKey } from "./translations";
import { translations } from "./translations";

// ---------------------------------------------------------------------------
// Locale context — provides the current language and a translation function
// ---------------------------------------------------------------------------

type LocaleContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
};

const LocaleContext = createContext<LocaleContextValue>({ locale: "en", setLocale: () => {} });

/**
 * Return a stable translation function bound to the current locale.
 * Format parameters: t("key", { count: 42 }) replaces "{count}" in the template.
 */
export function useT() {
  const { locale } = useContext(LocaleContext);
  return useCallback(
    (key: TranslationKey, params?: Record<string, string | number>) => {
      let text: string =
        translations[locale][key] ??
        translations.en[key] ??
        key;
      if (params) {
        for (const [k, v] of Object.entries(params)) {
          text = text.replace(`{${k}}`, String(v));
        }
      }
      return text;
    },
    [locale],
  );
}

/** Return the current locale value ("en" or "zh"). */
export function useLocale(): Locale {
  return useContext(LocaleContext).locale;
}

/** Return a locale setter. */
export function useSetLocale(): (locale: Locale) => void {
  return useContext(LocaleContext).setLocale;
}

export { LocaleContext };

/** Resolve the best initial locale from saved preference or browser language. */
export function resolveLocale(): Locale {
  try {
    const saved = localStorage.getItem("ids-prototype-locale");
    if (saved === "en" || saved === "zh") return saved;
  } catch {
    // localStorage unavailable (SSR / test env)
  }
  return "en";
}

export type { Locale };
