'use client';
import { ArrowRight } from 'lucide-react';
import { compact, LEVEL_COLOR, seconds, TACTIC_ORDER } from '@/lib/format';

export function Funnel({ stages }: { stages: { label: string; value: number; caption: string; time?: number }[] }) {
  const max = Math.max(1, ...stages.map((s) => s.value));
  return (
    <div className="grid gap-3 md:grid-cols-[repeat(4,minmax(0,1fr))]">
      {stages.map((s, i) => {
        const pct = Math.max(6, Math.round((Math.log10(s.value + 1) / Math.log10(max + 1)) * 100));
        return (
          <div key={s.label} className="relative rise" style={{ animationDelay: `${i * 70}ms` }}>
            <div className="rounded-xl bg-ink-850/80 p-4 ring-1 ring-line h-full">
              <div className="flex items-center justify-between text-[11px] uppercase tracking-[0.12em] text-fg-subtle">
                <span>{String(i + 1).padStart(2, '0')} · {s.label}</span>
                {s.time !== undefined && <span className="normal-case tracking-normal font-mono">{seconds(s.time)}</span>}
              </div>
              <div className="mt-2 text-2xl font-semibold tabular-nums">{compact.format(s.value)}</div>
              <div className="mt-1 text-xs text-fg-subtle">{s.caption}</div>
              <div className="mt-3 h-1.5 rounded-full bg-ink-700 overflow-hidden">
                <div className="h-full rounded-full bg-gradient-to-r from-brand to-brand-2" style={{ width: `${pct}%` }} />
              </div>
            </div>
            {i < stages.length - 1 && <ArrowRight className="absolute -right-3 top-1/2 z-10 hidden size-4 -translate-y-1/2 text-fg-subtle md:block" />}
          </div>
        );
      })}
    </div>
  );
}

export function Histogram({ values }: { values: number[] }) {
  const buckets = Array.from({ length: 10 }, (_, i) => ({ from: i * 10, n: 0 }));
  values.forEach((v) => { buckets[Math.min(9, Math.floor(v / 10))].n += 1; });
  const max = Math.max(1, ...buckets.map((b) => b.n));
  return (
    <div>
      <div className="flex h-40 items-end gap-1.5">
        {buckets.map((b) => {
          const color = b.from >= 80 ? LEVEL_COLOR.critical : b.from >= 70 ? LEVEL_COLOR.high : b.from >= 40 ? LEVEL_COLOR.medium : LEVEL_COLOR.low;
          return (
            <div key={b.from} className="group relative flex h-full flex-1 flex-col justify-end">
              <div className="rounded-t-md transition-all duration-700 group-hover:brightness-125" style={{ height: `${(b.n / max) * 100}%`, minHeight: b.n ? 4 : 0, background: `linear-gradient(180deg, ${color}, ${color}55)` }} />
              <div className="pointer-events-none absolute -top-7 left-1/2 -translate-x-1/2 rounded bg-ink-950 px-1.5 py-0.5 text-[11px] opacity-0 ring-1 ring-line group-hover:opacity-100 whitespace-nowrap">{b.n} incidents</div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex justify-between text-[10px] text-fg-subtle font-mono"><span>0</span><span>50</span><span>100</span></div>
    </div>
  );
}

export function TacticStrip({ counts, total }: { counts: Record<string, number>; total: number }) {
  const tactics = [...TACTIC_ORDER.filter((t) => counts[t] !== undefined), ...Object.keys(counts).filter((t) => !TACTIC_ORDER.includes(t))];
  if (!tactics.length) return null;
  return (
    <div className="grid grid-cols-[repeat(auto-fill,minmax(130px,1fr))] gap-2">
      {tactics.map((t) => {
        const share = counts[t] / Math.max(1, total);
        return (
          <div key={t} className="relative overflow-hidden rounded-lg p-3 ring-1 ring-line" style={{ background: `rgba(200,120,64,${0.06 + share * 0.45})` }}>
            <div className="text-[11px] leading-tight text-fg-muted">{t}</div>
            <div className="mt-1 text-lg font-semibold tabular-nums">{counts[t]}</div>
            <div className="text-[10px] text-fg-subtle">{Math.round(share * 100)}% of incidents</div>
          </div>
        );
      })}
    </div>
  );
}
