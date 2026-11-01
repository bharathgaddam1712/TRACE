'use client';
import { Crosshair, Info, Route } from 'lucide-react';
import type { Incident } from '@/lib/types';
import { Card, CardHeader, Chip, Empty, Mono, cx } from '@/components/ui';

const CONF = { high: '#b8432f', medium: '#c9902f', low: '#8a8780' } as const;

export function Lookahead({ incident }: { incident: Incident }) {
  const la = incident.lookahead;
  const rows = [...(la.reachable ?? [])].sort((a, b) => b.criticality - a.criticality || a.hops - b.hops);
  return (
    <Card>
      <CardHeader icon={<Route className="size-4" />} title="Where the attacker could go next"
        subtitle={`Possible next assets from incident accounts and hosts, based on access observed before the incident ended · ${la.total_candidates ?? rows.length} candidates`} />
      {rows.length === 0 ? (
        <div className="px-5 pb-5">
          <Empty title="Insufficient access evidence for a next asset">
            No additional host outside this incident met the access and time constraints.
          </Empty>
          <ul className="space-y-2 text-xs text-fg-muted">
            {(la.assumptions ?? []).filter((reason) => reason.startsWith('No ')).map((reason) => <li key={reason}>{reason}</li>)}
          </ul>
          <p className="mt-3 text-xs text-fg-subtle">This panel needs successful account access, privileged logons, or observed administrative network paths tied to this incident. External IP contacts alone do not establish access to another internal asset.</p>
        </div>
      ) : (
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
