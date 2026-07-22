import { useEffect, useMemo, useState } from "react";
import { Activity, Globe, Laptop, Network, Search, Server, ShieldAlert } from "lucide-react";

import { idsApi } from "../api/idsApi";
import type { TopologyEdgeRecord, TopologyNodeKind, TopologyNodeRecord, TopologySnapshot } from "../types";

interface PositionedNode extends TopologyNodeRecord {
  x: number;
  y: number;
}

const EMPTY_TOPOLOGY: TopologySnapshot = { nodes: [], edges: [] };
const MAX_VISIBLE_NODES = 60;
const VIEWBOX_WIDTH = 1200;
const VIEWBOX_HEIGHT = 760;

const nodeKindIcon: Record<TopologyNodeKind, typeof Laptop> = {
  workstation: Laptop, server: Server, gateway: Network, external: Globe,
};

const nodeKindLabel: Record<TopologyNodeKind, string> = {
  workstation: "Workstation", server: "Server", gateway: "Gateway", external: "External",
};

function planTopology(snapshot: TopologySnapshot): { nodes: PositionedNode[]; edges: TopologyEdgeRecord[]; hiddenNodes: number } {
  const weight = new Map<string, number>();
  snapshot.edges.forEach((edge) => {
    weight.set(edge.source, (weight.get(edge.source) ?? 0) + edge.packets);
    weight.set(edge.target, (weight.get(edge.target) ?? 0) + edge.packets);
  });

  const ranked = [...snapshot.nodes].sort((left, right) => {
    if (left.kind === "gateway" && right.kind !== "gateway") return -1;
    if (right.kind === "gateway" && left.kind !== "gateway") return 1;
    return (weight.get(right.id) ?? 0) - (weight.get(left.id) ?? 0) || left.ip.localeCompare(right.ip);
  });
  const retained = ranked.slice(0, MAX_VISIBLE_NODES);
  const retainedIds = new Set(retained.map((node) => node.id));
  const edges = snapshot.edges.filter((edge) => retainedIds.has(edge.source) && retainedIds.has(edge.target));
  if (!retained.length) return { nodes: [], edges: [], hiddenNodes: 0 };

  const center = retained[0];
  const internal = retained.slice(1).filter((node) => node.kind !== "external");
  const external = retained.slice(1).filter((node) => node.kind === "external");
  const primary = internal.slice(0, 16);
  const secondary = internal.slice(16);
  const positions = new Map<string, { x: number; y: number }>();
  positions.set(center.id, { x: VIEWBOX_WIDTH / 2, y: VIEWBOX_HEIGHT / 2 });
  placeRing(positions, primary, 220, 165, -Math.PI / 2);
  placeRing(positions, secondary, 375, 255, -Math.PI / 2 + 0.12);
  placeRing(positions, external, 525, 325, -Math.PI / 2 + 0.24);

  return {
    nodes: retained.map((node) => ({ ...node, ...(positions.get(node.id) ?? { x: VIEWBOX_WIDTH / 2, y: VIEWBOX_HEIGHT / 2 }) })),
    edges,
    hiddenNodes: Math.max(0, snapshot.nodes.length - retained.length),
  };
}

function placeRing(
  positions: Map<string, { x: number; y: number }>,
  nodes: TopologyNodeRecord[],
  radiusX: number,
  radiusY: number,
  phase: number,
) {
  nodes.forEach((node, index) => {
    const angle = phase + (Math.PI * 2 * index) / Math.max(nodes.length, 1);
    positions.set(node.id, {
      x: VIEWBOX_WIDTH / 2 + Math.cos(angle) * radiusX,
      y: VIEWBOX_HEIGHT / 2 + Math.sin(angle) * radiusY,
    });
  });
}

export function NetworkTopologyPage({ refreshVersion }: { refreshVersion: number }) {
  const [query, setQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [snapshot, setSnapshot] = useState<TopologySnapshot>(EMPTY_TOPOLOGY);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    idsApi.topology()
      .then((next) => {
        if (!active) return;
        setSnapshot(next);
        setSelectedNode((current) => current && next.nodes.some((node) => node.id === current) ? current : null);
        setError("");
      })
      .catch((reason) => {
        if (active) setError(reason instanceof Error ? reason.message : "Network topology could not be loaded.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => { active = false; };
  }, [refreshVersion]);

  const { nodes, edges, hiddenNodes } = useMemo(() => planTopology(snapshot), [snapshot]);
  const normalizedQuery = query.trim().toLowerCase();
  const matchingNodeIds = useMemo(() => new Set(
    nodes
      .filter((node) => !normalizedQuery || `${node.ip} ${node.label} ${node.role}`.toLowerCase().includes(normalizedQuery))
      .map((node) => node.id),
  ), [nodes, normalizedQuery]);
  const selected = selectedNode ? nodes.find((node) => node.id === selectedNode) : undefined;
  const connectedToSelected = edges.filter((edge) => selectedNode && (edge.source === selectedNode || edge.target === selectedNode));
  const workstationCount = nodes.filter((node) => node.kind === "workstation").length;
  const serverCount = nodes.filter((node) => node.kind === "server").length;
  const highRiskCount = nodes.filter((node) => node.risk >= 50).length;

  return (
    <div className="page-stack" data-refresh-version={refreshVersion}>
      <section className="topology-summary">
        <TopologyMetric icon={<Laptop size={15} />} label="Workstations" value={workstationCount} color="#2878d0" background="#dcecff" />
        <TopologyMetric icon={<Server size={15} />} label="Servers" value={serverCount} color="#2f8f66" background="#d8f3e6" />
        <TopologyMetric icon={<ShieldAlert size={15} />} label="High Risk" value={highRiskCount} color="#c2413b" background="#fde2e0" />
        <TopologyMetric icon={<Network size={15} />} label="Connections" value={edges.length} color="#6d7f90" background="#e5eaee" />
      </section>

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search observed hosts by name, IP or role" /></label>
        <span className="result-count">
          {matchingNodeIds.size} observed endpoints{hiddenNodes ? `, ${hiddenNodes} lower-volume endpoints hidden` : ""}
        </span>
      </section>

      <div className="topology-workspace">
        <div className="topology-stage">
          <div className="topology-legend">
            <strong>Observed packet topology</strong>
            <div>{(["workstation", "server", "gateway", "external"] as const).map((kind) => {
              const Icon = nodeKindIcon[kind];
              return <span key={kind} className="topology-legend-item"><span className={`topology-legend-dot topology-kind-${kind}`}><Icon size={12} /></span>{nodeKindLabel[kind]}</span>;
            })}</div>
          </div>
          <div className="topology-canvas-wrap" role="region" aria-label="Scrollable network topology canvas" tabIndex={0}>
            {loading && !nodes.length ? <p className="empty-state">Loading observed packet connections...</p> : null}
            {!loading && error && !nodes.length ? <p className="empty-state">Local API unavailable: {error}</p> : null}
            {!loading && !error && !nodes.length ? <p className="empty-state">No packet connections are stored yet. Start capture or import a PCAP to build the topology.</p> : null}
            {nodes.length ? <svg className="topology-canvas" width={VIEWBOX_WIDTH} height={VIEWBOX_HEIGHT} viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`} preserveAspectRatio="xMidYMid meet" aria-label="Observed network topology">
              <defs>
                <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
                <marker id="arrowhead" viewBox="0 0 7 6" refX="7" refY="3" markerWidth="7" markerHeight="6" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="#8899aa" /></marker>
              </defs>
              {edges.map((edge) => {
                const source = nodes.find((node) => node.id === edge.source);
                const target = nodes.find((node) => node.id === edge.target);
                if (!source || !target) return null;
                const highlighted = Boolean(selectedNode && (edge.source === selectedNode || edge.target === selectedNode));
                const filtered = Boolean(normalizedQuery && !matchingNodeIds.has(edge.source) && !matchingNodeIds.has(edge.target));
                return <line key={`${edge.source}-${edge.target}-${edge.protocol}`} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke={highlighted ? "var(--accent)" : "#8899aa"} strokeWidth={highlighted ? 2.5 : Math.min(2.2, 0.8 + Math.log10(edge.packets + 1) * 0.45)} strokeOpacity={filtered ? 0.05 : selectedNode ? (highlighted ? 0.9 : 0.1) : 0.32} markerEnd="url(#arrowhead)" />;
              })}
              {nodes.map((node) => {
                const isSelected = selectedNode === node.id;
                const isFiltered = Boolean(normalizedQuery && !matchingNodeIds.has(node.id));
                const Icon = nodeKindIcon[node.kind];
                const riskColor = node.risk >= 80 ? "#c2413b" : node.risk >= 50 ? "#d97706" : "#2f8f66";
                return <g key={node.id} transform={`translate(${node.x}, ${node.y})`} opacity={isFiltered ? 0.16 : 1} className="topology-node-group" onClick={() => setSelectedNode(node.id === selectedNode ? null : node.id)} style={{ cursor: "pointer" }}>
                  {isSelected && <circle cx={0} cy={0} r={34} fill="var(--accent)" opacity={0.08} filter="url(#glow)" />}
                  <circle cx={0} cy={0} r={22} fill={isSelected ? "var(--accent)" : "var(--surface)"} stroke={isSelected ? "var(--accent)" : "var(--border-strong)"} strokeWidth={isSelected ? 2 : 1.5} />
                  <foreignObject x={-15} y={-15} width={30} height={30}><div style={{ width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center", color: isSelected ? "#fff" : riskColor }}><Icon size={15} /></div></foreignObject>
                  {node.risk > 0 && <><circle cx={16} cy={-16} r={9} fill={riskColor} stroke="var(--surface)" strokeWidth={1.5} /><text x={16} y={-12} textAnchor="middle" fill="#fff" fontSize={8} fontWeight={700}>{node.risk}</text></>}
                  <text x={0} y={36} textAnchor="middle" fill="var(--text)" fontSize={10} fontWeight={600}>{compactLabel(node.label)}</text>
                  <text x={0} y={48} textAnchor="middle" fill="var(--muted)" fontSize={8}>{node.ip}</text>
                </g>;
              })}
            </svg> : null}
          </div>
          {error && nodes.length ? <p className="topology-refresh-error">Latest refresh failed: {error}</p> : null}
        </div>

        <aside className="topology-detail">
          {selected ? <>
            <header className="topology-detail-header"><h3>{selected.label}</h3><span className={`risk-score risk-${selected.risk >= 80 ? "high" : selected.risk >= 50 ? "medium" : "low"}`}>{selected.risk}</span></header>
            <dl className="detail-grid">
              <div><dt>IP Address</dt><dd>{selected.ip}</dd></div>
              <div><dt>Type</dt><dd>{nodeKindLabel[selected.kind]}</dd></div>
              <div><dt>Role</dt><dd>{selected.role}</dd></div>
              <div><dt>Last Seen</dt><dd>{selected.lastSeen || "Unknown"}</dd></div>
              <div><dt>Packets</dt><dd>{selected.packets.toLocaleString()}</dd></div>
              <div><dt>Alerts</dt><dd>{selected.alerts.toLocaleString()}</dd></div>
            </dl>
            <div className="topology-detail-section">
              <h3>Observed connections <span>{connectedToSelected.length}</span></h3>
              <div className="packet-stack">
                {connectedToSelected.map((edge) => {
                  const outbound = edge.source === selectedNode;
                  const peer = outbound ? edge.target : edge.source;
                  return <div key={`${edge.source}-${edge.target}-${edge.protocol}`} className="topology-connection-row"><strong>{outbound ? "To" : "From"} {peer}</strong><span>{edge.protocol} - {edge.packets.toLocaleString()} packets</span><small>{formatBytes(edge.bytes)} - last seen {edge.lastSeen || "unknown"}</small></div>;
                })}
                {!connectedToSelected.length && <p className="empty-hint">No connections recorded.</p>}
              </div>
            </div>
          </> : <div className="topology-empty-detail"><Activity size={24} /><p>Select a node in the topology graph to view its observed packet connections.</p></div>}
        </aside>
      </div>
    </div>
  );
}

function TopologyMetric({ icon, label, value, color, background }: { icon: React.ReactNode; label: string; value: number; color: string; background: string }) {
  return <div className="topo-stat"><div className="stat-icon" style={{ color, background }}>{icon}</div><div><span>{label}</span><strong>{value}</strong></div></div>;
}

function compactLabel(value: string) {
  return value.length > 22 ? `${value.slice(0, 19)}...` : value;
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
