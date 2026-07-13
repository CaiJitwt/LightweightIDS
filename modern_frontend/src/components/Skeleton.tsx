interface SkeletonProps {
  width?: string | number;
  height?: string | number;
  radius?: string | number;
  inline?: boolean;
}

export function Skeleton({ width = "100%", height = 16, radius = 4, inline = false }: SkeletonProps) {
  return (
    <span
      className="skeleton"
      aria-hidden="true"
      style={{ width: typeof width === "number" ? `${width}px` : width, height: typeof height === "number" ? `${height}px` : height, borderRadius: typeof radius === "number" ? `${radius}px` : radius, display: inline ? "inline-block" : "block" }}
    />
  );
}

export function SkeletonCard({ lines = 3 }: { lines?: number }) {
  return (
    <div className="skeleton-card">
      <Skeleton width="42%" height={18} />
      <Skeleton width="72%" height={13} />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} width={`${60 + Math.random() * 38}%`} height={12} />
      ))}
    </div>
  );
}

export function SkeletonMetric() {
  return (
    <div className="metric" aria-hidden="true">
      <Skeleton width={34} height={34} radius={5} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <Skeleton width={64} height={11} />
        <div style={{ marginTop: 5 }}><Skeleton width={72} height={22} /></div>
        <div style={{ marginTop: 5 }}><Skeleton width={96} height={10} /></div>
      </div>
    </div>
  );
}

export function SkeletonTable({ rows = 5, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div className="table-scroll" aria-hidden="true">
      <table className="data-table">
        <thead>
          <tr>
            {Array.from({ length: cols }).map((_, i) => (
              <th key={i}><Skeleton width={48 + i * 18} height={12} /></th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, r) => (
            <tr key={r}>
              {Array.from({ length: cols }).map((_, c) => (
                <td key={c}><Skeleton width={`${40 + Math.random() * 50}%`} height={12} /></td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
