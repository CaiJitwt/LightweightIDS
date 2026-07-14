import { useRef } from "react";
import { ImagePlus, Palette, PawPrint, RotateCcw } from "lucide-react";

export interface PersonalizationState {
  accent: string;
  background: string;
  petImage: string;
  petPosition: "bottom-right" | "bottom-left" | "top-right" | "top-left";
  petSize: number;
  petOpacity: number;
}

export function PersonalizationPage({ state, onChange }: { state: PersonalizationState; onChange: (next: PersonalizationState) => void }) {
  const backgroundPicker = useRef<HTMLInputElement>(null);
  const petPicker = useRef<HTMLInputElement>(null);
  const readImage = (event: React.ChangeEvent<HTMLInputElement>, key: "background" | "petImage") => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => onChange({ ...state, [key]: String(reader.result) });
    reader.readAsDataURL(file);
  };
  const reset = () => onChange({ accent: "#2677bd", background: "", petImage: "", petPosition: "bottom-right", petSize: 96, petOpacity: 85 });
  return <div className="page-stack settings-workspace">
    <section className="settings-section"><header className="section-heading"><div><h2>Workspace appearance</h2><p>Saved locally for this modern frontend profile</p></div><Palette size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>Accent color</strong><small>Used for navigation and interactive emphasis.</small></div><label className="color-picker"><input aria-label="Accent color" type="color" value={state.accent} onChange={(event) => onChange({ ...state, accent: event.target.value })} /><code>{state.accent}</code></label></div>
      <div className="setting-row"><div><strong>Wallpaper</strong><small>Choose an image for the workspace background.</small></div><div className="inline-actions"><input ref={backgroundPicker} className="visually-hidden" type="file" accept="image/png,image/jpeg,image/webp" onChange={(event) => readImage(event, "background")} /><button className="icon-text-button" type="button" onClick={() => backgroundPicker.current?.click()}><ImagePlus size={15} />Choose image</button><button className="icon-button" type="button" title="Clear wallpaper" onClick={() => onChange({ ...state, background: "" })}><RotateCcw size={15} /></button></div></div>
    </div></section>
    <section className="settings-section"><header className="section-heading"><div><h2>Overlay companion</h2><p>Transparent PNG overlay that never blocks analyst interactions</p></div><PawPrint size={17} /></header><div className="settings-body">
      <div className="setting-row"><div><strong>Pet image</strong><small>Transparent PNG and WebP images are supported.</small></div><div className="inline-actions"><input ref={petPicker} className="visually-hidden" type="file" accept="image/png,image/webp" onChange={(event) => readImage(event, "petImage")} /><button className="icon-text-button" type="button" onClick={() => petPicker.current?.click()}><ImagePlus size={15} />Choose image</button><button className="icon-button" type="button" title="Hide companion" onClick={() => onChange({ ...state, petImage: "" })}><RotateCcw size={15} /></button></div></div>
      <div className="setting-row"><div><strong>Position</strong></div><select className="plain-select" aria-label="Pet position" value={state.petPosition} onChange={(event) => onChange({ ...state, petPosition: event.target.value as PersonalizationState["petPosition"] })}><option value="bottom-right">Bottom right</option><option value="bottom-left">Bottom left</option><option value="top-right">Top right</option><option value="top-left">Top left</option></select></div>
      <Range label="Size" value={state.petSize} min={48} max={220} suffix="px" onChange={(value) => onChange({ ...state, petSize: value })} /><Range label="Opacity" value={state.petOpacity} min={20} max={100} suffix="%" onChange={(value) => onChange({ ...state, petOpacity: value })} />
    </div></section>
    <button className="icon-text-button reset-personalization" type="button" onClick={reset}><RotateCcw size={15} />Reset personalization</button>
  </div>;
}

function Range({ label, value, min, max, suffix, onChange }: { label: string; value: number; min: number; max: number; suffix: string; onChange: (value: number) => void }) {
  return <div className="setting-row"><div><strong>{label}</strong></div><label className="range-control"><input aria-label={label} type="range" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} /><span>{value}{suffix}</span></label></div>;
}
