'use client';
import Link from 'next/link';
import { useApi } from '@/lib/api';
import { seconds } from '@/lib/format';

type Run = { run_name?: string; published_at?: string; complete_demo_seconds?: number; source_bytes?: number; under_ten_minutes?: boolean };
type Model = { status: string; selected_model?: string };

export function RunSummary() {
  const run = useApi<Run>('/demo/timings', 15000).data;
  const model = useApi<Model>('/forecast/model', 15000).data;
  if (!run?.published_at && model?.status !== 'available') return null;
  return (
    <div className="mb-6 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 rounded-xl bg-ink-800 px-4 py-3 text-xs ring-1 ring-line">
      <div className="space-y-1">
        <Link href="/data" className="font-medium text-fg">Latest completed run: {run?.run_name ?? '—'}</Link>
        {run?.published_at && <div className="text-fg-muted">Published <time dateTime={run.published_at}>{new Date(run.published_at).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'long' })}</time></div>}
      </div>
      <div className="flex flex-wrap gap-x-5 gap-y-2">
        {run?.complete_demo_seconds !== undefined && <span className={run.under_ten_minutes ? 'text-low' : 'text-med'}>Measured end-to-end: <strong>{seconds(run.complete_demo_seconds)}</strong></span>}
        {run?.source_bytes !== undefined && <span className="text-fg-muted">Input: {(run.source_bytes / 1e9).toFixed(2)} GB</span>}
        {model?.status === 'available' && <Link href="/data" className="font-medium text-brand">Prediction model: {model.selected_model}</Link>}
      </div>
    </div>
  );
}
