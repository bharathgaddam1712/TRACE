'use client';
import cytoscape, { Core, ElementDefinition } from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Camera, Crosshair, Expand, Minimize, Search, Shrink } from 'lucide-react';
import type { Graph, GraphEdge, GraphNode } from '@/lib/types';
import { when } from '@/lib/format';
import { Chip, cx } from '@/components/ui';
import { EDGE_COLORS, EDGE_LABELS, entityView, isHypothesis, styleOf } from './model';

let registered = false;
function ensureLayouts() {
  if (!registered) { cytoscape.use(fcose); registered = true; }
}

const LAYOUTS: Record<string, cytoscape.LayoutOptions> = {
  organic: { name: 'fcose', animate: true, animationDuration: 500, quality: 'proof', nodeRepulsion: () => 9000, idealEdgeLength: () => 95, padding: 40 } as cytoscape.LayoutOptions,
  concentric: { name: 'concentric', animate: true, animationDuration: 500, padding: 40, concentric: (n: cytoscape.NodeSingular) => n.degree(false), levelWidth: () => 2, minNodeSpacing: 24 } as cytoscape.LayoutOptions,
  hierarchy: { name: 'breadthfirst', animate: true, animationDuration: 500, padding: 40, directed: true, spacingFactor: 1.15 },
  circle: { name: 'circle', animate: true, animationDuration: 500, padding: 40 },
  grid: { name: 'grid', animate: true, animationDuration: 500, padding: 40, avoidOverlap: true },
};

type Selection = { kind: 'node' | 'edge'; id: string } | null;

export default function GraphExplorer({ graph, path, onPick }: {
  graph: Graph; path?: string[]; onPick?: (nodeId: string) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [mode, setMode] = useState<'entities' | 'full'>('entities');
  const [layout, setLayout] = useState('organic');
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [showHyp, setShowHyp] = useState(true);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<Selection>(null);
  const [full, setFull] = useState(false);

  const view = useMemo(() => (mode === 'entities' ? entityView(graph) : graph), [graph, mode]);
  const nodes = useMemo(() => new Map(view.nodes.map((n) => [n.id, n])), [view]);
  const edgeById = useMemo(() => new Map(view.edges.map((e, i) => [`e${i}`, e])), [view]);
  const degree = useMemo(() => {
    const d = new Map<string, number>();
    view.edges.forEach((e) => [e.source, e.target].forEach((x) => d.set(x, (d.get(x) ?? 0) + 1)));
    return d;
  }, [view]);
  const legend = useMemo(() => {
    const seen = new Map<string, string>();
    view.nodes.forEach((n) => { const s = styleOf(n); seen.set(s.name, s.color); });
    return [...seen.entries()];
  }, [view]);

  // Build / rebuild the graph when the data or view mode changes.
  useEffect(() => {
    ensureLayouts();
    if (!box.current) return;
    const elements: ElementDefinition[] = [
      ...view.nodes.map((n) => {
        const s = styleOf(n);
        const label = String(n.label ?? n.id);
        return { data: { id: n.id, label: label.length > 30 ? `${label.slice(0, 28)}…` : label, color: s.color, shape: s.shape,
          kindName: s.name, suspected: Boolean(n.suspected), size: 24 + Math.min(degree.get(n.id) ?? 0, 14) * 3 } };
      }),
      ...view.edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, kind: e.kind,
        color: EDGE_COLORS[e.kind] ?? '#b3aea4', hyp: isHypothesis(e), label: EDGE_LABELS[e.kind] ?? e.kind } })),
    ];
    const cy = cytoscape({
      container: box.current, elements, minZoom: 0.1, maxZoom: 3.5,
      style: [
        { selector: 'node', style: { 'background-color': 'data(color)', shape: 'data(shape)' as never, width: 'data(size)', height: 'data(size)',
          label: 'data(label)', color: '#2a2925', 'font-size': 10, 'font-family': 'Inter, sans-serif', 'text-valign': 'bottom', 'text-margin-y': 6,
          'text-outline-color': '#f7f6f3', 'text-outline-width': 2.5, 'border-width': 2, 'border-color': '#f7f6f3', 'transition-property': 'opacity, border-color, border-width', 'transition-duration': 200 } },
        { selector: 'node[?suspected]', style: { 'border-color': '#b8432f', 'border-width': 4 } },
        { selector: 'edge', style: { width: 1.6, 'line-color': 'data(color)', 'target-arrow-color': 'data(color)', 'target-arrow-shape': 'triangle',
          'curve-style': 'bezier', 'arrow-scale': 0.85, opacity: 0.85, 'transition-property': 'opacity, width', 'transition-duration': 200 } },
        { selector: 'edge[kind="lateral"]', style: { width: 2.8 } },
        { selector: 'edge[kind="acted_on"]', style: { width: 2.2 } },
        { selector: 'edge[?hyp]', style: { 'line-style': 'dashed', opacity: 0.5 } },
        { selector: '.faded', style: { opacity: 0.07, 'text-opacity': 0 } },
        { selector: '.hit', style: { 'border-color': '#b8952e', 'border-width': 5 } },
        { selector: '.sel', style: { 'border-color': '#c87840', 'border-width': 5, 'overlay-color': '#c87840', 'overlay-opacity': 0.12, 'overlay-padding': 6 } },
        { selector: 'edge.label', style: { label: 'data(label)', 'font-size': 9, color: '#3a3833', 'text-rotation': 'autorotate', 'text-background-color': '#f7f6f3',
          'text-background-opacity': 0.9, 'text-background-padding': '2px', width: 3, opacity: 1 } },
        { selector: 'node.path', style: { 'border-color': '#3f7f7a', 'border-width': 5, opacity: 1, 'overlay-color': '#3f7f7a', 'overlay-opacity': 0.15, 'overlay-padding': 8 } },
        { selector: 'edge.path', style: { 'line-color': '#3f7f7a', 'target-arrow-color': '#3f7f7a', width: 4, opacity: 1 } },
      ],
      layout: LAYOUTS.organic,
    });
    cy.on('tap', 'node', (e) => setSelected({ kind: 'node', id: e.target.id() }));
    cy.on('tap', 'edge', (e) => setSelected({ kind: 'edge', id: e.target.id() }));
    cy.on('tap', (e) => { if (e.target === cy) setSelected(null); });
    cy.on('mouseover', 'node, edge', () => { if (box.current) box.current.style.cursor = 'pointer'; });
    cy.on('mouseout', 'node, edge', () => { if (box.current) box.current.style.cursor = 'default'; });
    cyRef.current = cy;
    setSelected(null);
    return () => { cy.destroy(); cyRef.current = null; };
  }, [view, degree]);

  // Visibility filters.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.nodes().forEach((n) => { n.style('display', hidden.has(n.data('kindName')) ? 'none' : 'element'); });
      cy.edges().forEach((e) => { e.style('display', !showHyp && e.data('hyp') ? 'none' : 'element'); });
    });
  }, [hidden, showHyp, view]);

  // Selection focus.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass('faded label sel');
    if (!selected) return;
    const el = cy.getElementById(selected.id);
    if (!el.length) return;
    const hood = el.isNode() ? el.closedNeighborhood() : (el as cytoscape.EdgeCollection).connectedNodes().union(el);
    cy.elements().not(hood).addClass('faded');
    el.addClass('sel');
    if (el.isEdge() || hood.edges().length <= 6) hood.edges().addClass('label');
    cy.animate({ fit: { eles: hood, padding: 70 } }, { duration: 350 });
  }, [selected]);

  // Path highlight from the path finder.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass('path');
    if (!path?.length) return;
    const ids = new Set(path);
    const onPath = cy.nodes().filter((n) => ids.has(n.id()));
    const pairs = new Set(path.slice(1).map((p, i) => [path[i], p].sort().join('|')));
    const edges = cy.edges().filter((e) => pairs.has([e.source().id(), e.target().id()].sort().join('|')));
    onPath.union(edges).addClass('path');
    if (onPath.length) cy.animate({ fit: { eles: onPath, padding: 80 } }, { duration: 400 });
  }, [path, view]);

  // Search.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().removeClass('hit');
    const q = query.trim().toLowerCase();
    if (!q) return;
    const hits = cy.nodes(':visible').filter((n) => String(nodes.get(n.id())?.label ?? n.id()).toLowerCase().includes(q));
    hits.addClass('hit');
    if (hits.length === 1) setSelected({ kind: 'node', id: hits[0].id() });
    else if (hits.length) cy.animate({ fit: { eles: hits, padding: 80 } }, { duration: 300 });
  }, [query, nodes]);

  useEffect(() => { const cy = cyRef.current; if (cy) setTimeout(() => { cy.resize(); cy.fit(undefined, 40); }, 60); }, [full]);

  const runLayout = (name: string) => { setLayout(name); cyRef.current?.layout(LAYOUTS[name]).run(); };
  const fit = () => { setSelected(null); cyRef.current?.animate({ fit: { eles: cyRef.current.elements(':visible'), padding: 40 } }, { duration: 300 }); };
  const png = () => {
    const cy = cyRef.current;
    if (!cy) return;
    const a = document.createElement('a');
    a.href = cy.png({ full: true, scale: 2, bg: '#f7f6f3' });
    a.download = 'trace-incident-graph.png';
    a.click();
  };

  const control = 'h-8 rounded-lg bg-ink-850 px-2.5 text-xs ring-1 ring-line outline-none hover:ring-line-strong focus:ring-brand/60';

  return (
    <div className={cx('flex flex-col gap-3', full && 'fixed inset-0 z-50 bg-ink-950 p-4')}>
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex rounded-lg bg-ink-850 p-0.5 ring-1 ring-line">
          {(['entities', 'full'] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)} className={cx('rounded-md px-3 py-1.5 text-xs font-medium', mode === m ? 'bg-ink-600 text-fg' : 'text-fg-muted hover:text-fg')}>
              {m === 'entities' ? 'Entities' : 'Full evidence'}
            </button>
          ))}
        </div>
        <label className="relative">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find user, host, IP…" className={cx(control, 'w-48 pl-8')} />
        </label>
        <select value={layout} onChange={(e) => runLayout(e.target.value)} className={control} aria-label="Layout">
          <option value="organic">Organic</option><option value="concentric">Concentric</option><option value="hierarchy">Hierarchy</option><option value="circle">Circle</option><option value="grid">Grid</option>
        </select>
        <label className={cx(control, 'flex cursor-pointer items-center gap-2')}><input type="checkbox" checked={showHyp} onChange={(e) => setShowHyp(e.target.checked)} className="accent-[#c87840]" />Hypotheses</label>
        <div className="ml-auto flex gap-1.5">
          <button onClick={fit} className={control} title="Fit to screen"><Shrink className="size-3.5" /></button>
          <button onClick={png} className={control} title="Export PNG"><Camera className="size-3.5" /></button>
          <button onClick={() => setFull((f) => !f)} className={control} title={full ? 'Exit full screen' : 'Full screen'}>{full ? <Minimize className="size-3.5" /> : <Expand className="size-3.5" />}</button>
        </div>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {legend.map(([name, color]) => {
          const off = hidden.has(name);
          return (
            <button key={name} onClick={() => setHidden((h) => { const n = new Set(h); if (off) n.delete(name); else n.add(name); return n; })}
              className={cx('flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] ring-1 transition', off ? 'text-fg-subtle ring-line opacity-50' : 'bg-ink-850 text-fg-muted ring-line-strong')}>
              <span className="size-2 rounded-full" style={{ background: color }} />{name}
            </button>
          );
        })}
        <span className="ml-2 flex items-center gap-3 text-[11px] text-fg-subtle">
          <span className="flex items-center gap-1"><span className="size-2 rounded-full ring-2 ring-crit" />suspected</span>
          <span style={{ color: '#c9902f' }}>━ lateral</span><span style={{ color: '#7d68a8' }}>━ logon</span><span style={{ color: '#c0564a' }}>━ network</span><span>┅ hypothesis</span>
        </span>
      </div>
      <div className={cx('grid gap-3 lg:grid-cols-[minmax(0,1fr)_340px]', full ? 'flex-1 min-h-0' : 'h-[640px]')}>
        <div className="relative min-h-[420px] overflow-hidden rounded-xl bg-[radial-gradient(circle_at_center,#fbfaf8,#f7f6f3)] ring-1 ring-line">
          <div ref={box} className="absolute inset-0 h-full w-full" />
          {view.nodes.length === 0 && <div className="absolute inset-0 grid place-items-center text-sm text-fg-subtle">No entities in this view. Try “Full evidence”.</div>}
        </div>
        <aside className="min-h-0 overflow-y-auto rounded-xl bg-ink-850/80 p-4 ring-1 ring-line scrollbar-thin">
          <SidePanel selected={selected} nodes={nodes} edges={view.edges} edgeById={edgeById} degree={degree}
            onSelect={setSelected} onPick={onPick} />
        </aside>
      </div>
    </div>
  );
}

function SidePanel({ selected, nodes, edges, edgeById, degree, onSelect, onPick }: {
  selected: Selection; nodes: Map<string, GraphNode>; edges: GraphEdge[]; edgeById: Map<string, GraphEdge>;
  degree: Map<string, number>; onSelect: (s: Selection) => void; onPick?: (id: string) => void;
}) {
  const back = <button onClick={() => onSelect(null)} className="mb-3 flex items-center gap-1 text-xs text-fg-subtle hover:text-fg"><ArrowLeft className="size-3.5" />Overview</button>;
  if (!selected) {
    const counts = new Map<string, number>();
    nodes.forEach((n) => counts.set(styleOf(n).name, (counts.get(styleOf(n).name) ?? 0) + 1));
    const top = [...nodes.values()].sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0)).slice(0, 8);
    return (
      <div>
        <h4 className="text-sm font-semibold">Incident graph</h4>
        <p className="mt-0.5 text-xs text-fg-subtle">{nodes.size} entities · {edges.length} relationships</p>
        <div className="mt-3 grid grid-cols-2 gap-2">
          {[...counts.entries()].map(([k, v]) => <div key={k} className="rounded-lg bg-ink-900/70 px-3 py-2 ring-1 ring-line"><div className="text-[11px] text-fg-subtle">{k}</div><div className="text-lg font-semibold tabular-nums">{v}</div></div>)}
        </div>
        <h5 className="mt-5 mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-fg-subtle">Most connected</h5>
        <ul className="space-y-1.5">
          {top.map((n) => (
            <li key={n.id}><button onClick={() => onSelect({ kind: 'node', id: n.id })} className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left ring-1 ring-line hover:ring-brand/50 hover:bg-ink-700/40">
              <span className="size-2.5 rounded-full shrink-0" style={{ background: styleOf(n).color }} />
              <span className="min-w-0 flex-1"><span className="block truncate text-[13px] font-medium">{n.label ?? n.id}</span>
                <span className="text-[11px] text-fg-subtle">{styleOf(n).name} · {degree.get(n.id) ?? 0} links{n.suspected && <span className="text-crit"> · suspected</span>}</span></span>
            </button></li>
          ))}
        </ul>
        <p className="mt-4 text-[11px] leading-relaxed text-fg-subtle">Click any user, host or IP to see exactly who it connects to. Scroll to zoom, drag to pan, drag nodes to rearrange.</p>
      </div>
    );
  }
  if (selected.kind === 'edge') {
    const e = edgeById.get(selected.id);
    if (!e) return back;
    return (
      <div>{back}
        <div className="text-[11px] uppercase tracking-[0.12em] text-fg-subtle">{EDGE_LABELS[e.kind] ?? e.kind}{isHypothesis(e) && ' · hypothesis'}</div>
        <h4 className="mt-1 text-sm font-semibold break-words">{nodes.get(e.source)?.label ?? e.source} → {nodes.get(e.target)?.label ?? e.target}</h4>
        <EdgeFacts e={e} />
      </div>
    );
  }
  const n = nodes.get(selected.id);
  if (!n) return back;
  const groups = new Map<string, { other: GraphNode; edge: GraphEdge; out: boolean }[]>();
  edges.forEach((e) => {
    if (e.source !== n.id && e.target !== n.id) return;
    const out = e.source === n.id;
    const other = nodes.get(out ? e.target : e.source);
    if (!other) return;
    const g = styleOf(other).group;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push({ other, edge: e, out });
  });
  const s = styleOf(n);
  return (
    <div>{back}
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.12em]" style={{ color: s.color }}><span className="size-2 rounded-full" style={{ background: s.color }} />{s.name}{n.role ? ` · ${n.role}` : ''}</div>
      <h4 className="mt-1 text-base font-semibold break-all">{n.label ?? n.id}</h4>
      {n.suspected && <div className="mt-1 text-xs font-medium text-crit">Suspected compromised</div>}
      <div className="mt-3 flex gap-2">
        <div className="flex-1 rounded-lg bg-ink-900/70 px-3 py-2 ring-1 ring-line"><div className="text-[11px] text-fg-subtle">Connections</div><div className="text-lg font-semibold tabular-nums">{degree.get(n.id) ?? 0}</div></div>
        <div className="flex-1 rounded-lg bg-ink-900/70 px-3 py-2 ring-1 ring-line"><div className="text-[11px] text-fg-subtle">Groups</div><div className="text-lg font-semibold tabular-nums">{groups.size}</div></div>
      </div>
      {onPick && <button onClick={() => onPick(n.id)} className="mt-3 flex w-full items-center justify-center gap-1.5 rounded-lg bg-ink-700 py-1.5 text-xs ring-1 ring-line-strong hover:bg-ink-600"><Crosshair className="size-3.5" />Use in path finder</button>}
      {[...groups.entries()].map(([g, list]) => (
        <div key={g} className="mt-4">
          <h5 className="mb-2 text-[11px] font-medium uppercase tracking-[0.12em] text-fg-subtle">{g} ({list.length})</h5>
          <ul className="space-y-1.5">
            {list.map(({ other, edge, out }, i) => (
              <li key={`${other.id}-${i}`}>
                <button onClick={() => onSelect({ kind: 'node', id: other.id })} className="w-full rounded-lg px-2.5 py-2 text-left ring-1 ring-line hover:ring-brand/50 hover:bg-ink-700/40">
                  <div className="flex items-center gap-1.5 text-[13px] font-medium"><span className="text-fg-subtle">{out ? '→' : '←'}</span><span className="truncate">{other.label ?? other.id}</span></div>
                  <div className="mt-0.5 text-[11px] text-fg-subtle">{EDGE_LABELS[edge.kind] ?? edge.kind}{isHypothesis(edge) && ' · hypothesis'}{edge.event_ids?.length ? ` · ${edge.event_ids.length} event${edge.event_ids.length === 1 ? '' : 's'}` : ''}</div>
                  {(edge.techniques?.length || edge.steps?.length) ? <div className="mt-1 flex flex-wrap gap-1">{edge.techniques?.map((t) => <Chip key={t} tone="brand">{t}</Chip>)}{edge.steps?.length ? <Chip tone="muted">step {edge.steps.join(', ')}</Chip> : null}</div> : null}
                  {edge.derived_via && <div className="mt-1 text-[10px] text-fg-subtle">via {edge.derived_via}</div>}
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function EdgeFacts({ e }: { e: GraphEdge }) {
  const rows: [string, React.ReactNode][] = [
    ['Techniques', e.techniques?.length ? <span className="flex flex-wrap gap-1">{e.techniques.map((t) => <Chip key={t} tone="brand">{t}</Chip>)}</span> : '—'],
    ['Steps', e.steps?.join(', ') || '—'], ['Events', e.event_ids?.length ?? 0],
    ['First seen', when(e.first_seen)], ['Last seen', when(e.last_seen)], ['Evidence', isHypothesis(e) ? 'hypothesis (not observed)' : 'observed'],
  ];
  if (e.derived_via) rows.push(['Via', e.derived_via]);
  return (
    <dl className="mt-3 space-y-2 text-[13px]">
      {rows.map(([k, v]) => <div key={k} className="flex gap-3"><dt className="w-24 shrink-0 text-fg-subtle">{k}</dt><dd className="min-w-0 break-words">{v}</dd></div>)}
    </dl>
  );
}

