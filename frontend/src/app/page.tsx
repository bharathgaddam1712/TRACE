'use client';
import Link from 'next/link';
import { Activity, ArrowUpRight, Clock, Cpu, Crosshair, Network, Radar, ShieldAlert, Users } from 'lucide-react';
import { useApi } from '@/lib/api';
import type { IncidentRow, Metrics } from '@/lib/types';
import { bytes, compact, number, seconds, title, when } from '@/lib/format';
import { Bars, Button, Card, CardHeader, Chip, Empty, ErrorBox, ScoreRing, Skeleton, Stat } from '@/components/ui';
import { Funnel, Histogram, TacticStrip } from '@/components/charts';

function tally(lists: (string[] | undefined)[]) {
  const counts: Record<string, number> = {};
  lists.forEach((list) => new Set(list ?? []).forEach((v) => { counts[v] = (counts[v] ?? 0) + 1; }));
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
}

export default function Overview() {
  const metrics = useApi<Metrics>('/metrics');
  const incidents = useApi<IncidentRow[]>('/incidents');
  if (metrics.error) return <ErrorBox error={metrics.error} />;
  const m = metrics.data;
  const rows = [...(incidents.data ?? [])].sort((a, b) => b.score - a.score);
  const ingest = (m?.ingest ?? {}) as Record<string, number>;
  const t = m?.timings ?? {};
  const critical = rows.filter((r) => r.score >= 85).length;
  const tactics = Object.fromEntries(tally(rows.map((r) => r.tactics)));
  const hosts = tally(rows.map((r) => r.entities?.hosts ?? r.hosts)).slice(0, 8);
  const users = tally(rows.map((r) => r.entities?.users ?? r.users)).slice(0, 8);
  const rules = Object.entries(m?.detect?.detections_by_rule ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const hostCount = new Set(rows.flatMap((r) => r.entities?.hosts ?? r.hosts ?? [])).size;
  const userCount = new Set(rows.flatMap((r) => r.entities?.users ?? r.users ?? [])).size;
  const span = ingest.ts_min_ms && ingest.ts_max_ms ? `${when(new Date(ingest.ts_min_ms).toISOString())} → ${when(new Date(ingest.ts_max_ms).toISOString())}` : '';

  return (
    <div className="space-y-6">
      <section className="grid items-center gap-10 py-6 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)] lg:py-12 rise">
        <div>
          <div className="eyebrow flex items-center gap-2"><Radar className="size-3.5" />Investigation overview</div>
          <h1 className="mt-5 font-display text-[54px] leading-[0.98] tracking-[-0.02em] sm:text-[76px]">
            {m && incidents.data ? <>{number.format(rows.length)} attack stories, <span className="text-gradient">told plainly.</span></> : <Skeleton className="h-20 w-[80%]" />}
          </h1>
          <p className="mt-6 max-w-xl text-[17px] leading-relaxed text-fg-muted">
            TRACE read {bytes(ingest.input_bytes)} of logs ({compact.format(ingest.events ?? 0)} events), matched {number.format(m?.rules?.loaded ?? 0)} detection rules, mapped every hit to MITRE ATT&amp;CK and linked related activity into ranked incidents.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-4">
            {rows[0] && <Link href={`/incidents/${rows[0].id}`}><Button variant="primary" className="px-6 py-3 text-[15px]">Investigate top incident →</Button></Link>}
            <Link href="/incidents" className="text-[15px] font-medium hover:underline underline-offset-4">Open the queue →</Link>
          </div>
          <p className="mt-8 font-mono text-[13px] text-fg-subtle">$ tracekc serve · {critical} critical · {number.format(m?.signals?.signals ?? 0)} signals</p>
        </div>
        <div className="panel relative overflow-hidden p-6">
          <div className="eyebrow">Dataset</div>
          <div className="inset mt-3 px-4 py-3 font-mono text-[12.5px] leading-6 text-fg-muted">
            <div>format&nbsp;&nbsp;{Object.keys((ingest as unknown as { formats?: Record<string, number> }).formats ?? {}).join(', ') || '—'}</div>
            <div>files&nbsp;&nbsp;&nbsp;{number.format(ingest.input_files ?? 0)} · {bytes(ingest.input_bytes)}</div>
            <div>events&nbsp;&nbsp;{number.format(ingest.events ?? 0)}</div>
            <div className="truncate">window&nbsp;&nbsp;{span || '—'}</div>
          </div>
          <div className="mt-5 grid grid-cols-3 gap-3 text-center">
            {[['Hosts', hostCount], ['Accounts', userCount], ['Rules hit', Object.keys(m?.detect?.detections_by_rule ?? {}).length]].map(([k, v]) => (
              <div key={k as string} className="rounded-2xl bg-ink-800 px-2 py-4 shadow-[0_8px_20px_-14px_#00000040] ring-1 ring-line">
                <div className="font-display text-[34px] leading-none">{v}</div>
                <div className="eyebrow mt-2 text-[10px]">{k}</div>
              </div>
            ))}
          </div>
          <p className="mt-5 text-center font-display text-lg italic text-fg-subtle">Evidence first. Every claim cites an event.</p>
        </div>
      </section>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Events analysed" value={m ? compact.format(ingest.valid_events ?? ingest.events ?? 0) : <Skeleton className="h-7 w-24" />} hint={`${number.format(ingest.duplicates_removed ?? 0)} duplicates · ${number.format(ingest.quarantined_rows ?? 0)} quarantined`} icon={<Activity className="size-4" />} accent="#3f7f7a" />
        <Stat label="Detections" value={m ? compact.format(m.signals?.signals ?? 0) : <Skeleton className="h-7 w-24" />} hint={`${number.format(m?.signals?.detections_merged ?? 0)} alerts merged into signals`} icon={<ShieldAlert className="size-4" />} accent="#c87840" />
        <Stat label="Incidents" value={incidents.data ? number.format(rows.length) : <Skeleton className="h-7 w-16" />} hint={<span><span className="text-crit font-medium">{critical} critical</span> · risk ≥ 85</span>} icon={<Network className="size-4" />} accent="#b8432f" />
        <Stat label="Processing time" value={m ? seconds(t.total_wall_seconds) : <Skeleton className="h-7 w-20" />} hint={`peak ${(m?.peak_process_tree_rss_gb ?? 0).toFixed(2)} GB memory`} icon={<Clock className="size-4" />} accent="#5d8f6a" />
      </div>

      <Card>
        <CardHeader title="From raw logs to attack stories" subtitle="Each stage narrows the data; time shows how long the stage took" icon={<Cpu className="size-4" />} />
        <div className="px-5 pb-5">
          {m ? <Funnel stages={[
            { label: 'Read', value: ingest.records_before_deduplication ?? ingest.events ?? 0, caption: `${bytes(ingest.input_bytes)} parsed into typed events`, time: t.ingest_seconds },
            { label: 'Detect', value: m.detect?.detections_by_rule ? Object.values(m.detect.detections_by_rule).reduce((a, b) => a + b, 0) : 0, caption: `${number.format(m.detect?.base_rules_evaluated ?? 0)} applicable rules evaluated`, time: t.detect_seconds },
            { label: 'Map & label', value: m.signals?.signals ?? 0, caption: 'signals with ATT&CK technique and tactic', time: t.label_seconds },
            { label: 'Link', value: rows.length, caption: `${number.format(m.output?.isolated_signals ?? 0)} isolated signals kept as findings`, time: (t.correlate_seconds ?? 0) + (t.materialize_seconds ?? 0) },
          ]} /> : <Skeleton className="h-28" />}
        </div>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader title="Priority incidents" subtitle="Highest risk first" icon={<ShieldAlert className="size-4" />}
            action={<Link href="/incidents" className="text-xs text-brand hover:underline">View all</Link>} />
          <ul className="divide-y divide-line">
            {incidents.loading && Array.from({ length: 5 }, (_, i) => <li key={i} className="px-5 py-4"><Skeleton className="h-10" /></li>)}
            {!incidents.loading && rows.length === 0 && <Empty title="No incidents yet">Run the pipeline to populate this dashboard.</Empty>}
            {rows.slice(0, 6).map((r, i) => (
              <li key={r.id} className="rise" style={{ animationDelay: `${i * 50}ms` }}>
                <Link href={`/incidents/${r.id}`} className="group flex items-center gap-4 px-5 py-3.5 hover:bg-ink-700/40 transition">
                  <ScoreRing score={r.score} size={46} stroke={4.5} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-[11px] text-fg-subtle"><span className="font-mono">#{r.id}</span><span>·</span><span>{when(r.first_seen)}</span></div>
                    <div className="truncate text-sm font-medium group-hover:text-fg">{title(r.title)}</div>
                    <div className="mt-1.5 flex flex-wrap gap-1">{(r.tactics ?? []).slice(0, 4).map((x) => <Chip key={x}>{x}</Chip>)}{(r.tactics?.length ?? 0) > 4 && <Chip tone="muted">+{r.tactics.length - 4}</Chip>}</div>
                  </div>
                  <div className="hidden text-right text-xs text-fg-subtle sm:block">
                    <div><span className="text-fg tabular-nums">{r.entities?.hosts?.length ?? r.hosts?.length ?? 0}</span> hosts</div>
                    <div><span className="text-fg tabular-nums">{r.signal_count ?? 0}</span> steps</div>
                  </div>
                  <ArrowUpRight className="size-4 text-fg-subtle opacity-0 transition group-hover:opacity-100" />
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <div className="space-y-6">
          <Card>
            <CardHeader title="Risk distribution" subtitle="Incidents by risk score" />
            <div className="px-5 pb-5">{incidents.data ? <Histogram values={rows.map((r) => r.score)} /> : <Skeleton className="h-40" />}</div>
          </Card>
          <Card>
            <CardHeader title="Top detection rules" subtitle="Raw rule hits before merging" />
            <div className="px-5 pb-5">{m ? <Bars rows={rules.map(([label, value]) => ({ label, value }))} /> : <Skeleton className="h-40" />}</div>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader title="Kill-chain coverage" subtitle="How many incidents reached each ATT&CK tactic, in attack order" icon={<Radar className="size-4" />} />
        <div className="px-5 pb-5"><TacticStrip counts={tactics} total={rows.length} /></div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Most involved hosts" subtitle="Number of incidents each host appears in" icon={<Network className="size-4" />} />
          <div className="px-5 pb-5">{hosts.length ? <Bars color="#4a74a0" rows={hosts.map(([label, value]) => ({ label, value }))} /> : <Empty title="No host data" />}</div>
        </Card>
        <Card>
          <CardHeader title="Most involved accounts" subtitle="Number of incidents each user appears in" icon={<Users className="size-4" />} />
          <div className="px-5 pb-5">{users.length ? <Bars color="#7d68a8" rows={users.map(([label, value]) => ({ label, value }))} /> : <Empty title="No account data">These logs carry no user names (common for firewall data).</Empty>}</div>
        </Card>
      </div>
    </div>
  );
}
