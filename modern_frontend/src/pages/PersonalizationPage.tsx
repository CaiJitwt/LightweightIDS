import { useRef, useState } from "react";
import { AlertTriangle, ImagePlus, Layers3, Palette, PawPrint, RotateCcw, TableProperties } from "lucide-react";
import { idsApi } from "../api/idsApi";
import type { PersonalizationState } from "../data/personalizationStore";
import { defaultPersonalization } from "../data/personalizationStore";
import { useT } from "../i18n/context";

const MAX_IMAGE_BYTES = 50 * 1024 * 1024;

const WALLPAPER_POSITIONS = ["center", "top-left", "top-right", "bottom-left", "bottom-right"] as const;
const WALLPAPER_SIZES = ["cover", "contain", "stretch", "original"] as const;

export function PersonalizationPage({ state, onChange, storageWarning, persistWarning }: { state: PersonalizationState; onChange: (next: PersonalizationState) => void; storageWarning?: boolean; persistWarning?: boolean }) {
  const t = useT();
  const backgroundPicker = useRef<HTMLInputElement>(null);
  const petPicker = useRef<HTMLInputElement>(null);
  const [warning, setWarning] = useState("");
  const [uploading, setUploading] = useState<"background" | "petImage" | "">("");
  const readImage = async (event: React.ChangeEvent<HTMLInputElement>, key: "background" | "petImage") => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_IMAGE_BYTES) {
      setWarning(t("personalization.uploadExceeded", { name: file.name }));
      return;
    }
    setWarning("");
    setUploading(key);
    try {
      const uploaded = await idsApi.uploadPersonalizationImage(key, file, file.name);
      onChange({ ...state, [key]: uploaded.url });
    } catch (error) {
      setWarning(error instanceof Error ? error.message : t("personalization.uploadFailed", { name: file.name }));
    } finally {
      setUploading("");
    }
  };
  const reset = () => { setWarning(""); onChange(defaultPersonalization); };
  return <div className="page-stack settings-workspace">
    <section className="settings-section"><header className="section-heading"><div><h2>{t("personalization.workspaceAppearance")}</h2><p>{t("personalization.workspaceMeta")}</p></div><Palette size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>{t("personalization.accentColor")}</strong><small>{t("personalization.accentColorMeta")}</small></div><label className="color-picker"><input aria-label={t("personalization.accentColor")} type="color" value={state.accent} onChange={(event) => onChange({ ...state, accent: event.target.value })} /><code>{state.accent}</code></label></div>
    </div></section>
    <section className="settings-section"><header className="section-heading"><div><h2>{t("personalization.componentSurfaces")}</h2><p>{t("personalization.componentMeta")}</p></div><Layers3 size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>{t("personalization.surfaceTint")}</strong><small>{t("personalization.surfaceTintMeta")}</small></div><label className="color-picker"><input aria-label={t("personalization.surfaceTint")} type="color" value={state.componentTint} onChange={(event) => onChange({ ...state, componentTint: event.target.value })} /><code>{state.componentTint}</code></label></div>
      <Range label={t("personalization.componentOpacity")} value={state.componentOpacity} min={65} max={100} suffix="%" onChange={(value) => onChange({ ...state, componentOpacity: value })} />
      <Range label={t("personalization.componentBlur")} value={state.componentBlur} min={0} max={24} suffix="px" onChange={(value) => onChange({ ...state, componentBlur: value })} />
    </div></section>
    <section className="settings-section"><header className="section-heading"><div><h2>{t("personalization.tableSurfaces")}</h2><p>{t("personalization.tableMeta")}</p></div><TableProperties size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>{t("personalization.tableTint")}</strong><small>{t("personalization.tableTintMeta")}</small></div><label className="color-picker"><input aria-label={t("personalization.tableTint")} type="color" value={state.tableTint} onChange={(event) => onChange({ ...state, tableTint: event.target.value })} /><code>{state.tableTint}</code></label></div>
      <Range label={t("personalization.tableOpacity")} value={state.tableOpacity} min={65} max={100} suffix="%" onChange={(value) => onChange({ ...state, tableOpacity: value })} />
      <Range label={t("personalization.tableBlur")} value={state.tableBlur} min={0} max={24} suffix="px" onChange={(value) => onChange({ ...state, tableBlur: value })} />
    </div></section>
    <section className="settings-section"><header className="section-heading"><div><h2>{t("personalization.wallpaper")}</h2><p>{t("personalization.wallpaperMeta")}</p></div><ImagePlus size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>{t("personalization.wallpaperLabel")}</strong><small>{t("personalization.wallpaperLabelMeta")}</small></div><div className="inline-actions"><input ref={backgroundPicker} className="visually-hidden" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => void readImage(event, "background")} /><button className="icon-text-button" type="button" disabled={Boolean(uploading)} onClick={() => backgroundPicker.current?.click()}><ImagePlus size={15} />{uploading === "background" ? t("personalization.saving") : t("personalization.chooseImage")}</button><button className="icon-button" type="button" title={t("personalization.clearWallpaper")} onClick={() => onChange({ ...state, background: "" })}><RotateCcw size={15} /></button></div></div>
      <div className="setting-row"><div><strong>{t("personalization.position")}</strong></div><select className="plain-select" aria-label={t("personalization.position")} value={state.backgroundPosition} onChange={(event) => onChange({ ...state, backgroundPosition: event.target.value as PersonalizationState["backgroundPosition"] })}>{WALLPAPER_POSITIONS.map((p) => <option key={p} value={p}>{p}</option>)}</select></div>
      <div className="setting-row"><div><strong>{t("personalization.size")}</strong></div><select className="plain-select" aria-label={t("personalization.size")} value={state.backgroundSize} onChange={(event) => onChange({ ...state, backgroundSize: event.target.value as PersonalizationState["backgroundSize"] })}>{WALLPAPER_SIZES.map((s) => <option key={s} value={s}>{s}</option>)}</select></div>
      <Range label={t("personalization.opacity")} value={state.backgroundOpacity} min={10} max={100} suffix="%" onChange={(value) => onChange({ ...state, backgroundOpacity: value })} />
    </div></section>
    <section className="settings-section"><header className="section-heading"><div><h2>{t("personalization.overlayCompanion")}</h2><p>{t("personalization.overlayMeta")}</p></div><PawPrint size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>{t("personalization.petImage")}</strong><small>{t("personalization.petImageMeta")}</small></div><div className="inline-actions"><input ref={petPicker} className="visually-hidden" type="file" accept="image/png,image/webp" onChange={(event) => void readImage(event, "petImage")} /><button className="icon-text-button" type="button" disabled={Boolean(uploading)} onClick={() => petPicker.current?.click()}><ImagePlus size={15} />{uploading === "petImage" ? t("personalization.saving") : t("personalization.chooseImage")}</button><button className="icon-button" type="button" title={t("personalization.hideCompanion")} onClick={() => onChange({ ...state, petImage: "" })}><RotateCcw size={15} /></button></div></div>
      <div className="setting-row"><div><strong>{t("personalization.position")}</strong></div><select className="plain-select" aria-label={t("personalization.position")} value={state.petPosition} onChange={(event) => onChange({ ...state, petPosition: event.target.value as PersonalizationState["petPosition"] })}><option value="bottom-right">{t("personalization.bottomRight")}</option><option value="bottom-left">{t("personalization.bottomLeft")}</option><option value="top-right">{t("personalization.topRight")}</option><option value="top-left">{t("personalization.topLeft")}</option></select></div>
      <Range label={t("personalization.size")} value={state.petSize} min={48} max={220} suffix="px" onChange={(value) => onChange({ ...state, petSize: value })} /><Range label={t("personalization.opacity")} value={state.petOpacity} min={20} max={100} suffix="%" onChange={(value) => onChange({ ...state, petOpacity: value })} />
    </div></section>
    {persistWarning && <div className="storage-warning" role="alert"><AlertTriangle size={15} />{t("personalization.resetWarning")}</div>}
    {warning && <div className="storage-warning" role="alert"><AlertTriangle size={15} />{warning}</div>}
    {storageWarning && !warning && <div className="storage-warning" role="alert"><AlertTriangle size={15} />{t("personalization.saveWarning")}</div>}
    <button className="icon-text-button reset-personalization" type="button" onClick={reset}><RotateCcw size={15} />{t("personalization.resetButton")}</button>
  </div>;
}

function Range({ label, value, min, max, suffix, onChange }: { label: string; value: number; min: number; max: number; suffix: string; onChange: (value: number) => void }) {
  return <div className="setting-row"><div><strong>{label}</strong></div><label className="range-control"><input aria-label={label} type="range" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} /><span>{value}{suffix}</span></label></div>;
}
