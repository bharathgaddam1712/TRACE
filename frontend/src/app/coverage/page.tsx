'use client';
import { useMemo, useState } from 'react';
import { BookCheck, Crosshair, Info, Search, ShieldCheck } from 'lucide-react';
import { useApi } from '@/lib/api';
import { number } from '@/lib/format';
import { Bars, Card, CardHeader, Chip, ErrorBox, Skeleton, Stat } from '@/components/ui';

type Coverage = {
  rules: { loaded?: number; rejected?: unknown[]; ruleset_hash?: string; covered_techniques?: string[];
    community?: { commit?: string; enabled?: number; unsupported?: number; excluded_status?: number; techniques?: number } };
  detection: { detections_by_source?: Record<string, number>; detections_by_rule?: Record<string, number>; rule_hit_events?: number };
  mapping: { attack_version?: string; by_tactic?: Record<string, number>; unmapped_techniques?: number };
  catalog_techniques: number; note: string;
};

export default function CoveragePage() {
  const { data, error } = useApi<Coverage>('/coverage');
  const [q, setQ] = useState('');
  const techniques = useMemo(() => data?.rules.covered_techniques ?? [], [data]);
  const grouped = useMemo(() => {
    const g = new Map<string, string[]>();
    techniques.filter((t) => t.toLowerCase().includes(q.trim().toLowerCase())).forEach((t) => {
      const base = t.split('.')[0];
      g.set(base, [...(g.get(base) ?? []), t]);
    });
    return [...g.entries()];
  }, [techniques, q]);
  if (error) return <ErrorBox error={error} />;
  if (!data) return <div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28" />)}<Skeleton className="h-96 md:col-span-4" /></div>;
  const parents = new Set(techniques.map((t) => t.split('.')[0])).size;
  const pct = data.catalog_techniques ? Math.round((techniques.length / data.catalog_techniques) * 100) : 0;
  const c = data.rules.community ?? {};
  const sources = Object.entries(data.detection.detections_by_source ?? {}).map(([label, value]) => ({ label, value }));
  const rules = Object.entries(data.detection.detections_by_rule ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([label, value]) => ({ label, value }));
  const tactics = Object.entries(data.mapping.by_tactic ?? {}).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));

  return (
    <div className="space-y-6">
      <header className="rise">
        <h1 className="font-display text-[52px] leading-none tracking-[-0.02em] sm:text-[64px]">Detection <span className="text-gradient">coverage</span></h1>
        <p className="mt-1 max-w-2xl text-sm text-fg-muted">Which MITRE ATT&CK techniques the loaded rules can detect, and which rules actually fired on this data.</p>
      </header>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Rules loaded" value={number.format(data.rules.loaded ?? 0)} hint={`${data.rules.rejected?.length ?? 0} rejected · hash ${data.rules.ruleset_hash ?? '—'}`} icon={<BookCheck className="size-4" />} />
        <Stat label="Techniques covered" value={techniques.length} hint={`${parents} parent techniques · ${pct}% of ATT&CK v${data.mapping.attack_version ?? '?'}`} icon={<Crosshair className="size-4" />} accent="#3f7f7a" />
        <Stat label="Community Sigma" value={number.format(c.enabled ?? 0)} hint={`${number.format(c.unsupported ?? 0)} unsupported · ${number.format(c.excluded_status ?? 0)} excluded`} icon={<ShieldCheck className="size-4" />} accent="#5d8f6a" />
        <Stat label="Rule hits" value={number.format(data.detection.rule_hit_events ?? 0)} hint={`${Object.keys(data.detection.detections_by_rule ?? {}).length} distinct rules fired`} accent="#c9902f" />
      </div>
      <Card className="p-5">
        <div className="flex items-center justify-between text-xs text-fg-subtle"><span>ATT&CK catalog coverage</span><span className="tabular-nums">{techniques.length} / {data.catalog_techniques}</span></div>
        <div className="mt-2 h-3 overflow-hidden rounded-full bg-ink-700"><div className="h-full rounded-full bg-gradient-to-r from-brand to-brand-2 transition-all duration-700" style={{ width: `${pct}%` }} /></div>
        <p className="mt-3 flex gap-2 text-xs text-fg-subtle"><Info className="size-3.5 shrink-0 mt-0.5" />{data.note}</p>
      </Card>
      <div className="grid gap-5 lg:grid-cols-3">
        <Card><CardHeader title="Detections by engine" /><div className="px-5 pb-5"><Bars rows={sources} color="#3f7f7a" /></div></Card>
        <Card><CardHeader title="Detections by tactic" subtitle="After ATT&CK mapping" /><div className="px-5 pb-5"><Bars rows={tactics} /></div></Card>
        <Card><CardHeader title="Top firing rules" /><div className="px-5 pb-5"><Bars rows={rules} color="#c9902f" /></div></Card>
      </div>
      <Card>
        <CardHeader title="Covered techniques" subtitle="Grouped by parent technique"
          action={<label className="relative"><Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter T1003…" className="h-8 w-44 rounded-lg bg-ink-900 pl-8 pr-3 text-xs ring-1 ring-line outline-none focus:ring-brand/60" /></label>} />
        <div className="grid gap-2 px-5 pb-5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {grouped.map(([base, list]) => (
            <div key={base} className="rounded-lg bg-ink-900/60 p-3 ring-1 ring-line">
              <a href={`https://attack.mitre.org/techniques/${base}/`} target="_blank" rel="noreferrer" className="font-mono text-[13px] font-semibold text-brand hover:underline">{base}</a>
              {list.length > 1 || list[0] !== base ? <div className="mt-1.5 flex flex-wrap gap-1">{list.filter((t) => t !== base).map((t) => <Chip key={t} tone="muted">.{t.split('.')[1]}</Chip>)}</div> : null}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
