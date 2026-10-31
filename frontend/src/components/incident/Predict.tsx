'use client';
import { Crosshair, Info, Route, Sparkles } from 'lucide-react';
import Link from 'next/link';
import { useApi } from '@/lib/api';
import type { Incident } from '@/lib/types';
import { Card, CardHeader, Chip, Empty, ErrorBox, KV, Mono, Skeleton, cx } from '@/components/ui';

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
            The separate historical technique model answers a different question: which ATT&amp;CK technique might follow.
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

export function NextTechnique({ incident }: { incident: Incident }) {
  const f = incident.forecast;
  const candidates = f?.candidates ?? [];
  return (
    <div className="space-y-5">
    <PredictionModel />
    <Card>
      <CardHeader icon={<Sparkles className="size-4" />} title="Likely next technique" subtitle="Learned from past incidents' technique sequences (time-bounded, no future data)" />
      {!f || (f.status !== 'available' && !candidates.length) ? (
        <Empty title="Forecast not available for this run">
          {f?.reason ?? 'No forecast was produced.'} Model details and an eligible example, when available, are shown above.
        </Empty>
      ) : (
        <div className="px-5 pb-5 space-y-2">
          {candidates.slice(0, 6).map((c, i) => {
            const share = c.historical_share === undefined ? null : Math.round(c.historical_share * 100);
            return (
              <div key={c.technique} className="flex items-center gap-3">
                <span className="w-5 text-right text-xs tabular-nums text-fg-subtle">{i + 1}</span>
                <Chip tone="brand">{c.technique}</Chip>
                {share === null ? <span className="flex-1 text-xs text-fg-subtle">Ranked by historical support</span> : <div className="h-2 flex-1 overflow-hidden rounded-full bg-ink-700"><div className="h-full rounded-full bg-gradient-to-r from-brand to-brand-2" style={{ width: `${Math.max(share, 3)}%` }} /></div>}
                <span className="w-16 text-right text-xs tabular-nums text-fg-muted">{share === null ? `rank ${i + 1}` : `${share}% share`}</span>
              </div>
            );
          })}
          {f.sequences?.slice(0, 3).map((s, i) => <div key={i} className="text-xs text-fg-subtle">Path: {s.techniques.join(' → ')}</div>)}
          {f.reason && <p className="text-xs text-med">{f.reason}</p>}
          {f.interpretation && <p className="pt-2 text-xs text-fg-subtle">{f.interpretation}</p>}
        </div>
      )}
    </Card>
    </div>
  );
}


type ModelSummary = {
  status: string; reason?: string; selected_model?: string; training_until?: string;
  training_incidents?: number; label_source?: string; eligible_incidents?: number;
  example_incident_id?: number | null; warnings?: string[];
  test?: Record<string, { transitions?: number; coverage?: number; top1?: number; mrr?: number }>;
};

export function PredictionModel() {
  const { data: model, error } = useApi<ModelSummary>('/forecast/model');
  if (error) return <ErrorBox error={error} />;
  if (!model) return <Skeleton className="h-44" />;
  const score = model.selected_model ? model.test?.[model.selected_model] : undefined;
  return (
    <Card>
      <CardHeader icon={<Sparkles className="size-4" />} title="Prediction model"
        subtitle="Chronological model comparison · historical technique sequences" />
      {model.status !== 'available' ? <Empty title="No fitted model">{model.reason}</Empty> : (
        <div className="px-5 pb-5 space-y-3">
          <KV rows={[
            ['Selected algorithm', model.selected_model ?? '—'],
            ['Training incidents', model.training_incidents ?? '—'],
            ['Training cutoff', model.training_until ?? '—'],
            ['Labels', model.label_source ?? 'unspecified'],
            ['Eligible incident forecasts', model.eligible_incidents ?? 0],
            ['Held-out transitions', score?.transitions ?? '—'],
          ]} />
          {score?.top1 !== undefined && <p className="text-xs text-fg-muted">Held-out label agreement: {(score.top1 * 100).toFixed(1)}%. Agreement with inferred labels does not establish attack-prediction accuracy.</p>}
          {model.warnings?.map((warning) => <p key={warning} className="text-xs text-med">{warning}</p>)}
          <div className="flex flex-wrap gap-4 text-xs font-medium text-brand">
            <a href="/api/forecast/model/download" download="forecast-model.json">Download fitted model JSON</a>
            {model.example_incident_id != null && <Link href={`/incidents/${model.example_incident_id}?tab=predict`}>Open an eligible prediction</Link>}
          </div>
          <p className="text-xs text-fg-subtle">Earlier incidents cannot use a model trained on later evidence. This model forecasts techniques; the separate temporal experiment ranks network interactions.</p>
        </div>
      )}
    </Card>
  );
}
