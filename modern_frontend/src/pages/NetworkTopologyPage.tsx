import { useMemo, useState } from "react";
import { Activity, Globe, Laptop, Network, Search, Server, ShieldAlert } from "lucide-react";
import { hosts } from "../data/mockData";
import type { HostRecord } from "../types";

interface TopologyNode {
  id: string;
  label: string;
  ip: string;
  kind: "workstation" | "server" | "gateway" | "external";
  risk: number;
  x: number;
  y: number;
}

interface TopologyEdge {
  source: string;
  target: string;
  protocol: string;
  packets: number;
}

const nodeKindIcon: Record<TopologyNode["kind"], typeof Laptop> = {
  workstation: Laptop, server: Server, gateway: Network, external: Globe,
};

const nodeKindLabel: Record<TopologyNode["kind"], string> = {
  workstation: "Workstation", server: "Server", gateway: "Gateway", external: "External",
};

const gatewayNode: TopologyNode = { id: "gw", label: "Default Gateway", ip: "10.0.0.1", kind: "gateway", risk: 5, x: 400, y: 40 };

function topologyFromHosts(list: HostRecord[]): { nodes: TopologyNode[]; edges: TopologyEdge[] } {
  const nodes: TopologyNode[] = [gatewayNode];
  const edges: TopologyEdge[] = [];

  list.forEach((host, index) => {
    const row = Math.floor(index / 2);
    const col = index % 2;
    nodes.push({
      id: host.ip, label: host.name, ip: host.ip,
      kind: host.role.includes("Server") ? "server" : "workstation",
      risk: host.risk, x: 120 + col * 440, y: 130 + row * 170,
    });
    edges.push({ source: host.ip, target: "gw", protocol: host.protocols?.[0]?.name ?? "TCP", packets: host.packets });
  });

  const externalServices = [
    { ip: "1.1.1.1", label: "Cloudflare DNS" },
    { ip: "8.8.8.8", label: "Google DNS" },
  ];
  externalServices.forEach((svc, i) => {
    nodes.push({ id: svc.ip, label: svc.label, ip: svc.ip, kind: "external", risk: 0, x: 200 + i * 360, y: 500 });
  });

  edges.push({ source: "1.1.1.1", target: "10.0.0.17", protocol: "DNS", packets: 820 });
  edges.push({ source: "8.8.8.8", target: "10.0.0.24", protocol: "DNS", packets: 340 });

  return { nodes, edges };
}

export function NetworkTopologyPage() {
  const [query, setQuery] = useState("");
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => topologyFromHosts(hosts), []);

  const visibleHosts = useMemo(() => {
    const q = query.toLowerCase();
    return hosts.filter((h) => `${h.ip} ${h.name} ${h.role}`.toLowerCase().includes(q));
  }, [query]);

  const selected = selectedNode ? nodes.find((n) => n.id === selectedNode) : undefined;
  const selectedHost = selectedNode ? hosts.find((h) => h.ip === selectedNode) : undefined;
  const connectedToSelected = edges.filter((e) => selectedNode && (e.source === selectedNode || e.target === selectedNode));

  const workstationCount = nodes.filter((n) => n.kind === "workstation").length;
  const serverCount = nodes.filter((n) => n.kind === "server").length;
  const highRiskCount = nodes.filter((n) => n.risk >= 50).length;

  return (
    <div className="page-stack">
      <section className="topology-summary">
        <div className="topo-stat">
          <div className="stat-icon" style={{ color: "#2878d0", background: "#dcecff" }}><Laptop size={15} /></div>
          <div><span>Workstations</span><strong>{workstationCount}</strong></div>
        </div>
        <div className="topo-stat">
          <div className="stat-icon" style={{ color: "#2f8f66", background: "#d8f3e6" }}><Server size={15} /></div>
          <div><span>Servers</span><strong>{serverCount}</strong></div>
        </div>
        <div className="topo-stat">
          <div className="stat-icon" style={{ color: "#c2413b", background: "#fde2e0" }}><ShieldAlert size={15} /></div>
          <div><span>High Risk</span><strong>{highRiskCount}</strong></div>
        </div>
        <div className="topo-stat">
          <div className="stat-icon" style={{ color: "#6d7f90", background: "#e5eaee" }}><Network size={15} /></div>
          <div><span>Connections</span><strong>{edges.length}</strong></div>
        </div>
      </section>

      <section className="filter-row">
        <label className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search hosts by name, IP or role" /></label>
        <span className="result-count">{visibleHosts.length} managed hosts</span>
      </section>

      <div className="topology-workspace">
        <div className="topology-stage">
          <div className="topology-legend">
            <strong>Observed network</strong>
            <div>{(["workstation", "server", "gateway", "external"] as const).map((kind) => {
              const Icon = nodeKindIcon[kind];
              return <span key={kind} className="topology-legend-item"><span className={`topology-legend-dot topology-kind-${kind}`}><Icon size={12} /></span>{nodeKindLabel[kind]}</span>;
            })}</div>
          </div>
          <div className="topology-canvas-wrap">
            <svg className="topology-canvas" viewBox="0 0 800 560" preserveAspectRatio="xMidYMid meet">
            <defs>
              <filter id="glow">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
              <marker id="arrowhead" viewBox="0 0 7 6" refX="7" refY="3" markerWidth="7" markerHeight="6" orient="auto">
                <path d="M0,0 L7,3 L0,6 Z" fill="#8899aa" />
              </marker>
            </defs>
            {edges.map((edge, i) => {
              const src = nodes.find((n) => n.id === edge.source);
              const tgt = nodes.find((n) => n.id === edge.target);
              if (!src || !tgt) return null;
              const isHighlighted = selectedNode && (edge.source === selectedNode || edge.target === selectedNode);
              return (
                <line
                  key={`edge-${i}`} x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                  stroke={isHighlighted ? "var(--accent)" : "#8899aa"}
                  strokeWidth={isHighlighted ? 2 : 1}
                  strokeOpacity={selectedNode ? (isHighlighted ? 0.9 : 0.12) : 0.35}
                  markerEnd="url(#arrowhead)"
                />
              );
            })}
            {nodes.map((node) => {
              const isSelected = selectedNode === node.id;
              const Icon = nodeKindIcon[node.kind];
              const riskColor = node.risk >= 80 ? "#c2413b" : node.risk >= 50 ? "#d97706" : "#2f8f66";
              return (
                <g key={node.id} transform={`translate(${node.x}, ${node.y})`} className="topology-node-group" onClick={() => setSelectedNode(node.id === selectedNode ? null : node.id)} style={{ cursor: "pointer" }}>
                  {isSelected && <circle cx={0} cy={0} r={34} fill="var(--accent)" opacity={0.08} filter="url(#glow)" />}
                  <circle cx={0} cy={0} r={22} fill={isSelected ? "var(--accent)" : "var(--surface)"} stroke={isSelected ? "var(--accent)" : "var(--border-strong)"} strokeWidth={isSelected ? 2 : 1.5} />
                  <foreignObject x={-15} y={-15} width={30} height={30}>
                    <div style={{ width: 30, height: 30, display: "flex", alignItems: "center", justifyContent: "center", color: isSelected ? "#fff" : riskColor }}>
                      <Icon size={15} />
                    </div>
                  </foreignObject>
                  {node.risk > 0 && (
                    <>
                      <circle cx={16} cy={-16} r={9} fill={riskColor} stroke="var(--surface)" strokeWidth={1.5} />
                      <text x={16} y={-12} textAnchor="middle" fill="#fff" fontSize={8} fontWeight={700}>{node.risk}</text>
                    </>
                  )}
                  <text x={0} y={36} textAnchor="middle" fill="var(--text)" fontSize={10} fontWeight={600}>{node.label}</text>
                  <text x={0} y={48} textAnchor="middle" fill="var(--muted)" fontSize={8}>{node.ip}</text>
                </g>
              );
            })}
            </svg>
          </div>
        </div>

        <aside className="topology-detail">
          {selected && selectedHost ? (
            <>
              <header className="topology-detail-header">
                <h3>{selected.label}</h3>
                <span className={`risk-score risk-${selectedHost.risk >= 80 ? "high" : selectedHost.risk >= 50 ? "medium" : "low"}`}>{selectedHost.risk}</span>
              </header>
              <dl className="detail-grid">
                <div><dt>IP Address</dt><dd>{selected.ip}</dd></div>
                <div><dt>Type</dt><dd>{nodeKindLabel[selected.kind]}</dd></div>
                <div><dt>Role</dt><dd>{selectedHost.role}</dd></div>
                <div><dt>Last Seen</dt><dd>{selectedHost.lastSeen}</dd></div>
              </dl>
              <div className="topology-detail-section">
                <h3>Connected edges <span>{connectedToSelected.length}</span></h3>
                <div className="packet-stack">
                  {connectedToSelected.map((edge, i) => (
                    <div key={i} style={{ padding: "6px 0", borderBottom: "1px solid var(--border)", fontSize: 10 }}>
                      <strong>{edge.source === selectedNode ? edge.source : edge.target}</strong>
                      <span style={{ color: "var(--muted)", marginLeft: 8 }}>to {edge.source === selectedNode ? edge.target : edge.source} - {edge.protocol}</span>
                      <small style={{ color: "var(--muted)", display: "block" }}>{edge.packets.toLocaleString()} packets</small>
                    </div>
                  ))}
                  {connectedToSelected.length === 0 && <p className="empty-hint">No connections recorded.</p>}
                </div>
              </div>
            </>
          ) : (
            <div className="topology-empty-detail">
              <Activity size={24} />
              <p>Select a node in the topology graph to view its details.</p>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
