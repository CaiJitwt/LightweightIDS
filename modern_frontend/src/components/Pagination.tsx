import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import { useT } from "../i18n/context";

interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
}

export function Pagination({ page, pageSize, total, onPageChange, onPageSizeChange }: PaginationProps) {
  const t = useT();
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const start = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const end = Math.min(page * pageSize, total);

  const pages = getPageNumbers(page, totalPages);

  return (
    <div className="pagination">
      <span className="pagination-info">
        {start}&ndash;{end} of {total}
      </span>
      <div className="pagination-controls">
        <button type="button" disabled={page <= 1} onClick={() => onPageChange(1)} title={t("common.firstPage")}>
          <ChevronsLeft size={15} />
        </button>
        <button type="button" disabled={page <= 1} onClick={() => onPageChange(page - 1)} title={t("common.previousPage")}>
          <ChevronLeft size={15} />
        </button>
        {pages.map((p, i) =>
          p === "…" ? (
            <span key={`gap-${i}`} className="pagination-gap">…</span>
          ) : (
            <button
              key={p}
              type="button"
              className={`pagination-page ${p === page ? "pagination-current" : ""}`}
              onClick={() => onPageChange(p)}
            >
              {p}
            </button>
          ),
        )}
        <button type="button" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)} title={t("common.nextPage")}>
          <ChevronRight size={15} />
        </button>
        <button type="button" disabled={page >= totalPages} onClick={() => onPageChange(totalPages)} title={t("common.lastPage")}>
          <ChevronsRight size={15} />
        </button>
      </div>
      {onPageSizeChange && (
        <label className="pagination-size">
          <select value={pageSize} onChange={(e) => onPageSizeChange(Number(e.target.value))}>
            {[10, 20, 50, 100].map((n) => (
              <option key={n} value={n}>{n}/page</option>
            ))}
          </select>
        </label>
      )}
    </div>
  );
}

function getPageNumbers(current: number, total: number): (number | "…")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages: (number | "…")[] = [1];
  if (current > 3) pages.push("…");
  const start = Math.max(2, current - 1);
  const end = Math.min(total - 1, current + 1);
  for (let i = start; i <= end; i++) pages.push(i);
  if (current < total - 2) pages.push("…");
  pages.push(total);
  return pages;
}
