'use client';
import { Crosshair, Info, Route, Sparkles } from 'lucide-react';
import type { Incident } from '@/lib/types';
import { Card, CardHeader, Chip, Empty, Mono, cx } from '@/components/ui';

const CONF = { high: '#b8432f', medium: '#c9902f', low: '#8a8780' } as const;

export function Lookahead({ incident }: { incident: Incident }) {
  const la = incident.lookahead;
  const rows = [...(la.reachable ?? [])].sort((a, b) => b.criticality - a.criticality || a.hops - b.hops);
  return (
    <Card>
      <CardHeader icon={<Route className="size-4" />} title="Where the attacker could go next"
        subtitle={`Assets reachable from compromised accounts and hosts, using access actually observed before the incident ended · ${la.total_candidates ?? rows.length} candidates`} />
      {rows.length === 0 ? <Empty title="No reachable assets found">{la.status === 'evidenced' ? 'Nothing beyond the incident was reachable with observed access.' : `Lookahead status: ${la.status}`}</Empty> : (
        <div className="px-5 pb-5">
          <div className="grid gap-2.5 sm:grid-cols-2">
            {rows.map((r, i) => (
              <div key={`${r.asset}-${i}`} className="rounded-xl bg-ink-900/60 p-3.5 ring-1 ring-line hover:ring-line-strong transition">
                <div className="flex items-center gap-2">
                  <Crosshair className="size-4 shrink-0" style={{ color: CONF[r.confidence] }} />
                  <span className="truncate text-[13px] font-semibold">{r.asset}</span>
                  <span className="ml-auto rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider" style={{ color: CONF[r.confidence], background: `${CONF[r.confidence]}1a` }}>{r.confidence}</span>
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5"><Chip tone="brand">{r.relation}</Chip><Chip tone="muted">via {r.via}</Chip><Chip tone="muted">{r.hops} hop{r.hops === 1 ? '' : 's'}</Chip></div>
                <div className="mt-2 flex items-center gap-1.5">
                  <span className="text-[11px] text-fg-subtle">Criticality</span>
                  {[1, 2, 3].map((n) => <span key={n} className={cx('h-1.5 w-5 rounded-full', n <= r.criticality ? 'bg-high' : 'bg-ink-700')} />)}
                </div>
                {r.evidence?.sample_event_id && <div className="mt-2 text-[11px] text-fg-subtle">evidence <Mono>{r.evidence.sample_event_id.slice(0, 13)}…</Mono></div>}
              </div>
            ))}
          </div>
          <p className="mt-4 flex gap-2 text-xs text-fg-subtle"><Info className="size-3.5 shrink-0 mt-0.5" />Possible access, not proof of compromise or of a future action. Confidence reflects how directly the access was observed.</p>
        </div>
      )}
    </Card>
  );
}

export function NextTechnique({ incident }: { incident: Incident }) {
  const f = incident.forecast;
  const candidates = f?.candidates ?? [];
  return (
    <Card>
      <CardHeader icon={<Sparkles className="size-4" />} title="Likely next technique" subtitle="Learned from past incidents' technique sequences (time-bounded, no future data)" />
      {!f || (f.status !== 'available' && !candidates.length) ? (
        <Empty title="Forecast not available for this run">
          {f?.reason ?? 'No forecast was produced.'} Train one with <Mono>tracekc train-forecast</Mono> on historical incidents, then <Mono>tracekc attach-forecast</Mono>.
        </Empty>
      ) : (
        <div className="px-5 pb-5 space-y-2">
          {candidates.slice(0, 6).map((c, i) => {
            const share = Math.round((c.historical_share ?? 0) * 100);
            return (
              <div key={c.technique} className="flex items-center gap-3">
                <span className="w-5 text-right text-xs tabular-nums text-fg-subtle">{i + 1}</span>
                <Chip tone="brand">{c.technique}</Chip>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-700"><div className="h-full rounded-full bg-gradient-to-r from-brand to-brand-2" style={{ width: `${Math.max(share, 3)}%` }} /></div>
                <span className="w-10 text-right text-xs tabular-nums text-fg-muted">{share}%</span>
              </div>
            );
          })}
          {f.sequences?.slice(0, 3).map((s, i) => <div key={i} className="text-xs text-fg-subtle">Path: {s.techniques.join(' → ')}</div>)}
          {f.interpretation && <p className="pt-2 text-xs text-fg-subtle">{f.interpretation}</p>}
        </div>
      )}
    </Card>
  );
}
