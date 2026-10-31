import type { Graph, GraphEdge, GraphNode } from '@/lib/types';

export interface NodeStyle { name: string; color: string; shape: string; group: string }

export const NODE_TYPES: Record<string, NodeStyle> = {
  user: { name: 'User', color: '#7d68a8', shape: 'ellipse', group: 'Users' },
  host: { name: 'Host', color: '#4a74a0', shape: 'round-rectangle', group: 'Hosts' },
  external: { name: 'External IP', color: '#c0564a', shape: 'diamond', group: 'IP addresses' },
  ip: { name: 'IP address', color: '#c0564a', shape: 'diamond', group: 'IP addresses' },
  domain: { name: 'Domain', color: '#cf8a4c', shape: 'hexagon', group: 'Domains' },
  event: { name: 'Detection step', color: '#b8952e', shape: 'round-tag', group: 'Detection steps' },
  signal: { name: 'Detection step', color: '#b8952e', shape: 'round-tag', group: 'Detection steps' },
  process: { name: 'Process', color: '#5d8f6a', shape: 'round-rectangle', group: 'Processes' },
  file: { name: 'File', color: '#8a8780', shape: 'rectangle', group: 'Files' },
  registry: { name: 'Registry key', color: '#3f7f7a', shape: 'barrel', group: 'Registry' },
  incident: { name: 'Incident', color: '#c87840', shape: 'round-octagon', group: 'Incidents' },
};
const FALLBACK: NodeStyle = { name: 'Other', color: '#b5b0a7', shape: 'ellipse', group: 'Other' };
export const ENTITY_TYPES = new Set(['user', 'host', 'external', 'ip', 'domain']);

export const EDGE_LABELS: Record<string, string> = {
  acted_on: 'logged on / acted on', lateral: 'lateral movement', outbound: 'outbound connection', inbound: 'inbound connection',
  could_reach: 'could reach', observed_on: 'detected on', contacted: 'contacted', ran: 'ran process', generated: 'generated',
  touched: 'touched file', modified: 'modified', correlates_with: 'correlates with',
};

export const EDGE_COLORS: Record<string, string> = {
  lateral: '#c9902f', acted_on: '#7d68a8', outbound: '#c0564a', contacted: '#c0564a', inbound: '#c0564a',
};

export function nodeType(node: GraphNode): string {
  const kind = node.type || node.id.split(':', 1)[0];
  if (NODE_TYPES[kind]) return kind;
  return node.id.startsWith('signal:') ? 'event' : kind;
}
export function styleOf(node: GraphNode) { return NODE_TYPES[nodeType(node)] ?? FALLBACK; }
export function isHypothesis(edge: GraphEdge) {
  return edge.kind === 'could_reach' || edge.evidence_kind === 'hypothesis' || edge.evidence_kind === 'inferred';
}

/** Users, hosts, IPs and domains only; host->domain/IP contact is rebuilt through collapsed detection steps. */
export function entityView(graph: Graph): Graph {
  const nodes = new Map(graph.nodes.map((n) => [n.id, n]));
  const keep = new Set([...nodes.values()].filter((n) => ENTITY_TYPES.has(nodeType(n))).map((n) => n.id));
  const edges: GraphEdge[] = graph.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
  const via = new Map<string, [string, GraphEdge][]>();
  for (const e of graph.edges) {
    for (const [here, there] of [[e.source, e.target], [e.target, e.source]]) {
      if (nodes.has(here) && !keep.has(here) && keep.has(there)) {
        if (!via.has(here)) via.set(here, []);
        via.get(here)!.push([there, e]);
      }
    }
  }
  const seen = new Set(edges.map((e) => `${e.source}|${e.target}|${e.kind}`));
  via.forEach((links, step) => {
    const hosts = links.filter(([n]) => nodeType(nodes.get(n)!) === 'host');
    const remote = links.filter(([n]) => ['domain', 'external', 'ip'].includes(nodeType(nodes.get(n)!)));
    for (const [host, first] of hosts) for (const [target, second] of remote) {
      const key = `${host}|${target}|contacted`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({ id: `via-${edges.length}`, source: host, target, kind: 'contacted', evidence_kind: 'observed_association',
        derived_via: nodes.get(step)?.label ?? step,
        techniques: [...new Set([...(first.techniques ?? []), ...(second.techniques ?? [])])].sort(),
        steps: [...new Set([...(first.steps ?? []), ...(second.steps ?? [])])].sort((a, b) => a - b),
        event_ids: [...new Set(second.event_ids ?? [])].slice(0, 100), first_seen: second.first_seen, last_seen: second.last_seen });
    }
  });
  return { nodes: graph.nodes.filter((n) => keep.has(n.id)), edges };
}
