'use client';
import Link from 'next/link';
import { useMemo, useState } from 'react';
import { ArrowDownWideNarrow, Filter, Search, Siren } from 'lucide-react';
import { useApi } from '@/lib/api';
import type { IncidentRow } from '@/lib/types';
import { duration, number, scoreLevel, TACTIC_ORDER, title, when } from '@/lib/format';
import { Card, Chip, cx, Empty, ErrorBox, LevelBadge, ScoreRing, Skeleton } from '@/components/ui';

type Sort = 'score' | 'recent' | 'steps';
const STATUS_TONE: Record<string, string> = { new: 'text-brand-2', investigating: 'text-med', contained: 'text-high', closed: 'text-low' };

export default function IncidentsPage() {
  const { data, error, loading } = useApi<IncidentRow[]>('/incidents?limit=1000', 30000);
  const [q, setQ] = useState('');
  const [minScore, setMinScore] = useState(0);
  const [tactic, setTactic] = useState('');
  const [status, setStatus] = useState('');
  const [sort, setSort] = useState<Sort>('score');

  const tactics = useMemo(() => {
    const all = new Set((data ?? []).flatMap((r) => r.tactics ?? []));
    return [...TACTIC_ORDER.filter((t) => all.has(t)), ...[...all].filter((t) => !TACTIC_ORDER.includes(t))];
  }, [data]);

  const rows = useMemo(() => {
    const needle = q.toLowerCase().trim();
    const filtered = (data ?? []).filter((r) => r.score >= minScore && (!tactic || r.tactics?.includes(tactic)) && (!status || r.status === status)
      && (!needle || JSON.stringify([r.id, r.title, r.entities, r.hosts, r.users, r.technique_ids]).toLowerCase().includes(needle)));
    const by: Record<Sort, (a: IncidentRow, b: IncidentRow) => number> = {
      score: (a, b) => b.score - a.score,
      recent: (a, b) => b.first_seen.localeCompare(a.first_seen),
      steps: (a, b) => (b.signal_count ?? 0) - (a.signal_count ?? 0),
    };
    return filtered.sort(by[sort]);
  }, [data, q, minScore, tactic, status, sort]);

  if (error) return <ErrorBox error={error} />;
  const select = 'h-9 rounded-lg bg-ink-850 px-3 text-[13px] ring-1 ring-line outline-none focus:ring-brand/60';

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4 rise">
        <div>
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-brand-2"><Siren className="size-3.5" />Incident queue</div>
          <h1 className="mt-3 font-display text-[52px] leading-none tracking-[-0.02em] sm:text-[64px]">Incidents</h1>
          <p className="mt-1 text-sm text-fg-muted">{loading ? 'Loading…' : `${number.format(rows.length)} of ${number.format(data?.length ?? 0)} incidents match`}</p>
        </div>
        <div className="flex gap-2 text-xs">
          {(['critical', 'high', 'medium', 'low'] as const).map((lvl) => (
            <span key={lvl} className="rounded-lg bg-ink-850 px-3 py-2 ring-1 ring-line"><LevelBadge level={lvl}>{lvl}</LevelBadge>
              <span className="ml-2 tabular-nums text-fg">{(data ?? []).filter((r) => scoreLevel(r.score) === lvl).length}</span></span>
          ))}
        </div>
      </div>

      <Card className="p-3">
        <div className="flex flex-wrap items-center gap-2">
          <label className="relative flex-1 min-w-[220px]">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-fg-subtle" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search by title, host, user, IP or technique"
              className="h-9 w-full rounded-lg bg-ink-850 pl-9 pr-3 text-[13px] ring-1 ring-line outline-none placeholder:text-fg-subtle focus:ring-brand/60" />
          </label>
          <div className="flex h-9 items-center gap-3 rounded-lg bg-ink-850 px-3 ring-1 ring-line">
            <Filter className="size-3.5 text-fg-subtle" /><span className="text-xs text-fg-subtle">Risk ≥</span>
            <input type="range" min={0} max={100} step={5} value={minScore} onChange={(e) => setMinScore(+e.target.value)} className="w-28 accent-[#c87840]" aria-label="Minimum risk score" />
            <span className="w-6 text-right text-xs tabular-nums">{minScore}</span>
          </div>
          <select value={tactic} onChange={(e) => setTactic(e.target.value)} className={select} aria-label="Tactic"><option value="">All tactics</option>{tactics.map((t) => <option key={t}>{t}</option>)}</select>
          <select value={status} onChange={(e) => setStatus(e.target.value)} className={select} aria-label="Case status"><option value="">Any status</option>{['new', 'investigating', 'contained', 'closed'].map((s) => <option key={s}>{s}</option>)}</select>
          <div className="flex h-9 items-center gap-1 rounded-lg bg-ink-850 p-1 ring-1 ring-line">
            <ArrowDownWideNarrow className="mx-1 size-3.5 text-fg-subtle" />
            {(['score', 'recent', 'steps'] as Sort[]).map((s) => (
              <button key={s} onClick={() => setSort(s)} className={cx('rounded-md px-2.5 py-1 text-xs capitalize', sort === s ? 'bg-ink-600 text-fg' : 'text-fg-muted hover:text-fg')}>{s}</button>
            ))}
          </div>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="hidden grid-cols-[72px_minmax(0,2.4fr)_minmax(0,1.6fr)_120px_110px_110px] gap-4 border-b border-line px-5 py-3 text-[11px] font-medium uppercase tracking-[0.1em] text-fg-subtle lg:grid">
          <span>Risk</span><span>Incident</span><span>Tactics</span><span>Scope</span><span>Duration</span><span>Status</span>
        </div>
        {loading && Array.from({ length: 8 }, (_, i) => <div key={i} className="px-5 py-4"><Skeleton className="h-11" /></div>)}
        {!loading && rows.length === 0 && <Empty title="No incidents match these filters">Try lowering the risk threshold or clearing the search.</Empty>}
        <ul className="divide-y divide-line">
          {rows.map((r) => (
            <li key={r.id}>
              <Link href={`/incidents/${r.id}`} className="group grid grid-cols-[56px_minmax(0,1fr)] items-center gap-4 px-5 py-3.5 transition hover:bg-ink-700/40 lg:grid-cols-[72px_minmax(0,2.4fr)_minmax(0,1.6fr)_120px_110px_110px]">
                <ScoreRing score={r.score} size={46} stroke={4.5} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-[11px] text-fg-subtle"><span className="font-mono">#{r.id}</span><span>{when(r.first_seen)}</span></div>
                  <div className="truncate text-[13.5px] font-medium group-hover:text-fg" title={title(r.title)}>{title(r.title)}</div>
                </div>
                <div className="col-span-2 flex flex-wrap gap-1 lg:col-span-1">
                  {(r.tactics ?? []).slice(0, 3).map((t) => <Chip key={t}>{t}</Chip>)}
                  {(r.tactics?.length ?? 0) > 3 && <Chip tone="muted">+{r.tactics.length - 3}</Chip>}
                </div>
                <div className="hidden text-xs text-fg-muted lg:block">
                  <div><span className="tabular-nums text-fg">{r.entities?.hosts?.length ?? r.hosts?.length ?? 0}</span> hosts · <span className="tabular-nums text-fg">{r.entities?.users?.length ?? r.users?.length ?? 0}</span> users</div>
                  <div><span className="tabular-nums text-fg">{r.signal_count ?? 0}</span> steps</div>
                </div>
                <div className="hidden font-mono text-xs text-fg-muted lg:block">{duration(r.first_seen, r.last_seen) || '—'}</div>
                <div className="hidden lg:block"><span className={cx('text-xs font-medium capitalize', STATUS_TONE[r.status ?? 'new'])}>● {r.status ?? 'new'}</span></div>
              </Link>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
