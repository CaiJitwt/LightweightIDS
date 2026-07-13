import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Search } from "lucide-react";

interface CommandAction {
  key: string;
  label: string;
  icon?: React.ReactNode;
  category: string;
  shortcut?: string;
}

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  actions: CommandAction[];
  onSelect: (key: string) => void;
}

export function CommandPalette({ open, onClose, actions, onSelect }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    if (!query.trim()) return actions;
    const q = query.toLowerCase();
    return actions.filter(
      (a) =>
        a.label.toLowerCase().includes(q) ||
        a.category.toLowerCase().includes(q),
    );
  }, [actions, query]);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIndex(0);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [filtered.length]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
        return;
      }
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => Math.min(prev + 1, filtered.length - 1));
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => Math.max(prev - 1, 0));
        return;
      }
      if (e.key === "Enter") {
        e.preventDefault();
        const action = filtered[selectedIndex];
        if (action) {
          onSelect(action.key);
          onClose();
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, filtered, selectedIndex, onSelect, onClose]);

  useEffect(() => {
    const el = containerRef.current?.querySelector(`[data-cmd-index="${selectedIndex}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [selectedIndex]);

  if (!open) return null;

  return (
    <div className="command-overlay" onClick={onClose}>
      <div className="command-palette" onClick={(e) => e.stopPropagation()} ref={containerRef}>
        <div className="command-input-wrap">
          <Search size={15} className="command-search-icon" />
          <input
            ref={inputRef}
            className="command-input"
            placeholder="Jump to a page, search alerts or hosts..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <kbd className="command-esc-hint">esc</kbd>
        </div>
        {filtered.length === 0 ? (
          <div className="command-empty">No matching pages or actions.</div>
        ) : (
          <div className="command-results">
            {filtered.map((action, index) => (
              <button
                key={action.key}
                type="button"
                className={`command-item ${index === selectedIndex ? "command-selected" : ""}`}
                data-cmd-index={index}
                onMouseEnter={() => setSelectedIndex(index)}
                onClick={() => {
                  onSelect(action.key);
                  onClose();
                }}
              >
                <div className="command-item-left">
                  {action.icon && <span className="command-item-icon">{action.icon}</span>}
                  <div className="command-item-meta">
                    <strong>{action.label}</strong>
                    <small>{action.category}</small>
                  </div>
                </div>
                {action.shortcut && <kbd>{action.shortcut}</kbd>}
                {index === selectedIndex && <ArrowRight size={15} className="command-indicator" />}
              </button>
            ))}
          </div>
        )}
        <footer className="command-footer">
          <span><kbd>↑↓</kbd> Navigate</span>
          <span><kbd>↵</kbd> Open</span>
          <span><kbd>esc</kbd> Dismiss</span>
        </footer>
      </div>
    </div>
  );
}
