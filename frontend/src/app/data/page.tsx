'use client';
import { Cpu, Database, FileCheck2, Gauge, Timer } from 'lucide-react';
import { useApi } from '@/lib/api';
import type { Metrics, Progress } from '@/lib/types';
import { bytes, number, seconds, when } from '@/lib/format';
import { Bars, Card, CardHeader, Chip, ErrorBox, KV, Mono, Skeleton, Stat } from '@/components/ui';

type Schemas = { version: number; normalized_required: string[]; formats: Record<string, Record<string, string>> };

export default function DataPage() {
  const metrics = useApi<Metrics>('/metrics');
  const progress = useApi<Progress>('/progress', 3000);
  const schemas = useApi<Schemas>('/parser-schemas');
  if (metrics.error) return <ErrorBox error={metrics.error} />;
  const m = metrics.data;
  if (!m) return <div className="grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28" />)}<Skeleton className="h-80 md:col-span-4" /></div>;
  const i = (m.ingest ?? {}) as Record<string, number> & { formats?: Record<string, number> };
  const t = m.timings ?? {};
  const stages = ['ingest', 'detect', 'label', 'correlate', 'materialize'].map((s) => ({ label: s, value: t[`${s}_seconds`] ?? 0 }));
  const rejected = (i.quarantined_rows ?? 0) + (i.adapter_rejected_records ?? 0) + (i.reader_rejected_records ?? 0);
  const quality = [
    ['Missing timestamp', i.missing_timestamp], ['Missing host', i.missing_host], ['Missing user', i.missing_user],
    ['Duplicates removed', i.duplicates_removed], ['Quarantined rows', i.quarantined_rows], ['Adapter rejected', i.adapter_rejected_records],
    ['Reader rejected', i.reader_rejected_records], ['Hosts with IPs', i.hosts_with_ips],
  ] as const;
  const p = progress.data;
  const pct = p?.source_bytes ? Math.round(((p.completed_bytes ?? 0) / p.source_bytes) * 100) : p?.state === 'complete' ? 100 : 0;

  return (
    <div className="space-y-6">
      <header className="rise">
        <h1 className="font-display text-[52px] leading-none tracking-[-0.02em] sm:text-[64px]">Data & <span className="text-gradient">pipeline</span></h1>
        <p className="mt-1 max-w-2xl text-sm text-fg-muted">What was read, how clean it was, and where the time went.</p>
      </header>
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Events" value={number.format(i.events ?? 0)} hint={`${i.input_files ?? 0} file(s) · ${bytes(i.input_bytes)}`} icon={<Database className="size-4" />} />
        <Stat label="Input quality" value={<span className="text-lg">{(m.input_quality ?? 'unknown').replace(/_/g, ' ')}</span>} hint={`${rejected} records rejected`} icon={<FileCheck2 className="size-4" />} accent={rejected ? '#c9902f' : '#5d8f6a'} />
        <Stat label="Wall time" value={seconds(t.total_wall_seconds)} hint={`${number.format(Math.round((i.events ?? 0) / Math.max(t.total_wall_seconds ?? 1, 0.001)))} events/s`} icon={<Timer className="size-4" />} accent="#3f7f7a" />
        <Stat label="Peak memory" value={`${(m.peak_process_tree_rss_gb ?? 0).toFixed(2)} GB`} hint={`limit ${String(m.machine?.memory_limit ?? '—')} · ${String(m.machine?.cpus ?? '?')} CPUs`} icon={<Cpu className="size-4" />} accent="#7d68a8" />
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <Card><CardHeader icon={<Gauge className="size-4" />} title="Stage timings" subtitle="Seconds per pipeline stage" />
          <div className="px-5 pb-5"><Bars rows={stages} color="#3f7f7a" format={(v) => seconds(v)} /></div></Card>
        <Card><CardHeader title="Run status" subtitle="Live from progress.json"
          action={p && <Chip tone={p.state === 'complete' ? 'cyan' : 'brand'}><span className="live-dot" />{p.state}</Chip>} />
          <div className="px-5 pb-5 space-y-4">
            <div className="h-2.5 overflow-hidden rounded-full bg-ink-700"><div className="h-full rounded-full bg-gradient-to-r from-brand to-brand-2 transition-all" style={{ width: `${pct}%` }} /></div>
            <KV rows={[['Stage', p?.stage ?? '—'], ['Read', `${bytes(p?.completed_bytes)} of ${bytes(p?.source_bytes)}`], ['Chunks', p?.chunks ?? '—'],
              ['Data window', i.ts_min_ms ? `${when(new Date(i.ts_min_ms).toISOString())} → ${when(new Date(i.ts_max_ms).toISOString())}` : '—'],
              ['Formats', Object.entries(i.formats ?? {}).map(([k, v]) => `${k} (${v})`).join(', ') || '—'], ['Parquet', bytes(i.parquet_bytes)], ['Pipeline', `v${m.version ?? '?'} · ATT&CK ${m.attack_mapping_version ?? '?'}`]]} />
            {p?.error && <p className="text-xs text-crit">{p.error}</p>}
          </div></Card>
      </div>
      <Card><CardHeader title="Ingest quality" subtitle="Zero is good — every non-zero count is explained in run_metrics.json" />
        <div className="grid grid-cols-2 gap-2 px-5 pb-5 md:grid-cols-4">
          {quality.map(([k, v]) => (
            <div key={k} className="rounded-lg bg-ink-900/60 px-4 py-3 ring-1 ring-line">
              <div className="text-[11px] text-fg-subtle">{k}</div>
              <div className={`mt-0.5 text-lg font-semibold tabular-nums ${v && k !== 'Hosts with IPs' ? 'text-med' : ''}`}>{number.format(v ?? 0)}</div>
            </div>
          ))}
        </div></Card>
      <Card><CardHeader title="Supported log formats" subtitle={`Parser contract v${schemas.data?.version ?? '?'} · required normalized fields: ${schemas.data?.normalized_required?.join(', ') ?? '…'}`} />
        <div className="grid gap-3 px-5 pb-5 md:grid-cols-2 xl:grid-cols-3">
          {Object.entries(schemas.data?.formats ?? {}).map(([name, f]) => (
            <div key={name} className="rounded-xl bg-ink-900/60 p-4 ring-1 ring-line">
              <div className="flex items-center gap-2"><Mono className="text-sm font-semibold text-brand">{name}</Mono></div>
              <dl className="mt-2 space-y-1.5 text-xs">{Object.entries(f).map(([k, v]) => <div key={k}><dt className="inline text-fg-subtle">{k.replace(/_/g, ' ')}: </dt><dd className="inline text-fg-muted">{String(v)}</dd></div>)}</dl>
            </div>
          ))}
        </div></Card>
    </div>
  );
}
