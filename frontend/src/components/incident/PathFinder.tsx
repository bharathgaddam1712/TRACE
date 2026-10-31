'use client';
import { useMemo, useState } from 'react';
import { ArrowRight, Clock, Loader2, Route } from 'lucide-react';
import { api } from '@/lib/api';
import type { Graph, PathResult } from '@/lib/types';
import { Button, Chip, cx } from '@/components/ui';
import { styleOf } from '@/components/graph/model';

const field = 'h-9 w-full rounded-lg bg-ink-900 px-3 text-[13px] ring-1 ring-line outline-none focus:ring-brand/60';

export function PathFinder({ incidentId, graph, source, target, setSource, setTarget, onPath }: {
  incidentId: number; graph: Graph; source: string; target: string;
  setSource: (s: string) => void; setTarget: (s: string) => void; onPath: (nodes: string[]) => void;
}) {
  const [mode, setMode] = useState<'shortest' | 'temporal'>('shortest');
  const [hyp, setHyp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PathResult | null>(null);
  const [err, setErr] = useState('');
  const options = useMemo(() => graph.nodes.filter((n) => styleOf(n).group !== 'Detection steps')
    .sort((a, b) => String(a.label ?? a.id).localeCompare(String(b.label ?? b.id))), [graph]);
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;

  const find = async () => {
    setBusy(true); setErr(''); setResult(null);
    const q = new URLSearchParams({ source, target });
    if (mode === 'shortest') { q.set('directed', 'false'); q.set('include_hypotheses', String(hyp)); }
    try {
      const r = await api<PathResult>(`/incidents/${incidentId}/${mode === 'shortest' ? 'shortest-path' : 'temporal-path'}?${q}`);
      setResult(r); onPath(r.nodes ?? []);
    } catch (e) { setErr((e as Error).message); onPath([]); } finally { setBusy(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-[13px] font-semibold"><Route className="size-4 text-brand" />Path finder
        <span className="text-xs font-normal text-fg-subtle">— how did the attacker get from A to B?</span></div>
      <div className="grid gap-2 md:grid-cols-[1fr_auto_1fr_auto_auto]">
        <select value={source} onChange={(e) => setSource(e.target.value)} className={field} aria-label="From">
          <option value="">From…</option>{options.map((n) => <option key={n.id} value={n.id}>{styleOf(n).name}: {n.label ?? n.id}</option>)}
        </select>
        <ArrowRight className="hidden size-4 self-center text-fg-subtle md:block" />
        <select value={target} onChange={(e) => setTarget(e.target.value)} className={field} aria-label="To">
          <option value="">To…</option>{options.map((n) => <option key={n.id} value={n.id}>{styleOf(n).name}: {n.label ?? n.id}</option>)}
        </select>
        <div className="flex rounded-lg bg-ink-900 p-0.5 ring-1 ring-line">
          {(['shortest', 'temporal'] as const).map((m) => (
            <button key={m} onClick={() => setMode(m)} title={m === 'temporal' ? 'Only hops that happened in time order' : 'Fewest hops'}
              className={cx('flex items-center gap-1 rounded-md px-3 text-xs font-medium', mode === m ? 'bg-ink-600 text-fg' : 'text-fg-muted')}>
              {m === 'temporal' && <Clock className="size-3" />}{m === 'shortest' ? 'Shortest' : 'Time-ordered'}
            </button>
          ))}
        </div>
        <Button variant="primary" onClick={find} disabled={!source || !target || source === target || busy}>{busy && <Loader2 className="size-3.5 animate-spin" />}Find path</Button>
      </div>
      {mode === 'shortest' && <label className="flex items-center gap-2 text-xs text-fg-subtle"><input type="checkbox" checked={hyp} onChange={(e) => setHyp(e.target.checked)} className="accent-[#c87840]" />Allow hypothesis edges (could-reach)</label>}
      {err && <p className="text-xs text-crit">{err}</p>}
      {result && (result.status === 'found' && result.nodes?.length ? (
        <div className="flex flex-wrap items-center gap-1.5 rounded-lg bg-brand-2/5 p-3 ring-1 ring-brand-2/25 rise">
          {result.nodes.map((n, i) => (
            <span key={`${n}-${i}`} className="flex items-center gap-1.5">{i > 0 && <ArrowRight className="size-3 text-brand-2" />}<Chip tone="cyan">{label(n)}</Chip></span>
          ))}
          <span className="ml-auto text-xs text-fg-subtle">{result.hops} hop{result.hops === 1 ? '' : 's'}</span>
          {result.interpretation && <p className="w-full pt-1 text-xs text-fg-subtle">{result.interpretation}</p>}
        </div>
      ) : <p className="rounded-lg bg-ink-900/60 p-3 text-xs text-fg-muted ring-1 ring-line">No path found{result.reason ? ` — ${result.reason}` : ''}. Try the other mode or allow hypothesis edges.</p>)}
    </div>
  );
}
