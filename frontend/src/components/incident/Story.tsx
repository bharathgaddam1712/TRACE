'use client';
import { useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, FileSearch, Loader2, X } from 'lucide-react';
import { api } from '@/lib/api';
import type { Incident, TimelineStep } from '@/lib/types';
import { LEVEL_COLOR, severity, when } from '@/lib/format';
import { Card, CardHeader, Chip, LevelBadge, Mono, cx } from '@/components/ui';

export function Narrative({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const lines = text.split('\n').filter((l) => l.trim());
  const shown = open ? lines : lines.slice(0, 6);
  return (
    <Card>
      <CardHeader title="Analyst narrative" subtitle="Generated from cited evidence only" />
      <div className="px-5 pb-4 space-y-1.5 text-[13px] leading-relaxed text-fg-muted">
        {shown.map((l, i) => <p key={i} className={cx(l.startsWith('#') && 'pt-2 font-semibold text-fg')}>{l.replace(/^#+\s*/, '')}</p>)}
        {lines.length > 6 && <button onClick={() => setOpen(!open)} className="pt-1 text-xs font-medium text-brand hover:underline">{open ? 'Show less' : `Show all ${lines.length} lines`}</button>}
      </div>
    </Card>
  );
}

export function Timeline({ incident }: { incident: Incident }) {
  const [evidence, setEvidence] = useState<{ id: string; data?: Record<string, unknown>; error?: string } | null>(null);
  const open = async (id: string) => {
    setEvidence({ id });
    try { setEvidence({ id, data: await api<Record<string, unknown>>(`/incidents/${incident.id}/evidence/${encodeURIComponent(id)}`) }); }
    catch (e) { setEvidence({ id, error: (e as Error).message }); }
  };
  return (
    <>
      <Card>
        <CardHeader title="Attack timeline" subtitle={`${incident.timeline.length} steps in time order — each step is one detection mapped to ATT&CK`} />
        <ol className="relative px-5 pb-5">
          {incident.timeline.map((s, i) => <Step key={s.step} s={s} last={i === incident.timeline.length - 1} onEvidence={open} />)}
        </ol>
      </Card>
      {evidence && <EvidenceDrawer {...evidence} onClose={() => setEvidence(null)} />}
    </>
  );
}

function Step({ s, last, onEvidence }: { s: TimelineStep; last: boolean; onEvidence: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const level = severity(s.severity);
  const color = LEVEL_COLOR[level];
  const flow = [s.user && `user ${s.user}`, s.host && `on ${s.host}`, s.src_ip && `from ${s.src_ip}`,
    (s.dst_host || s.dst_ip || s.dst_domain) && `→ ${s.dst_host || s.dst_domain || s.dst_ip}`].filter(Boolean).join(' ');
  return (
    <li className="relative flex gap-4 pl-1">
      <div className="flex flex-col items-center">
        <span className="mt-4 grid size-7 shrink-0 place-items-center rounded-full text-[11px] font-semibold tabular-nums ring-2"
          style={{ color, background: `${color}14`, boxShadow: `0 0 14px ${color}33`, borderColor: color, ['--tw-ring-color' as string]: `${color}66` }}>{s.step}</span>
        {!last && <span className="w-px flex-1 bg-gradient-to-b from-line-strong to-line" />}
      </div>
      <div className="min-w-0 flex-1 py-3">
        <button onClick={() => setOpen(!open)} className="group w-full rounded-xl px-3 py-2.5 text-left ring-1 ring-transparent hover:bg-ink-700/30 hover:ring-line">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[13px] font-semibold text-fg">{s.title}</span>
            <LevelBadge level={level} />
            {s.technique && <Chip tone="brand" title={s.technique_name}>{s.technique}{s.technique_name ? ` · ${s.technique_name}` : ''}</Chip>}
            {s.tactic && <Chip tone="muted">{s.tactic}</Chip>}
            {s.vendor_corroborated && <Chip tone="cyan">vendor corroborated</Chip>}
            <ChevronDown className={cx('ml-auto size-4 text-fg-subtle transition', open && 'rotate-180')} />
          </div>
          <div className="mt-1 flex flex-wrap gap-x-4 text-xs text-fg-subtle">
            <span>{when(s.ts)}</span>{flow && <span className="text-fg-muted">{flow}</span>}
            {s.event_count ? <span>{s.event_count} events</span> : null}
          </div>
        </button>
        {open && (
          <div className="mx-3 mt-2 space-y-3 rounded-xl bg-ink-900/60 p-4 ring-1 ring-line rise">
            {s.mapping_reason && <p className="text-xs leading-relaxed text-fg-muted"><span className="text-fg-subtle">Why this technique: </span>{s.mapping_reason}</p>}
            {s.rule_ids?.length ? <div className="flex flex-wrap gap-1.5"><span className="text-xs text-fg-subtle">Rules</span>{s.rule_ids.map((r) => <Chip key={r}>{r}</Chip>)}</div> : null}
            {s.event_ids?.length ? (
              <div>
                <div className="mb-1.5 text-xs text-fg-subtle">Evidence events — click to open the raw normalized record</div>
                <div className="flex flex-wrap gap-1.5">
                  {s.event_ids.slice(0, 12).map((id) => (
                    <button key={id} onClick={() => onEvidence(id)} className="flex items-center gap-1.5 rounded-md bg-ink-800 px-2 py-1 font-mono text-[11px] text-fg-muted ring-1 ring-line hover:text-fg hover:ring-brand/50">
                      <FileSearch className="size-3" />{id.length > 18 ? `${id.slice(0, 16)}…` : id}
                    </button>
                  ))}
                  {s.event_ids.length > 12 && <span className="self-center text-xs text-fg-subtle">+{s.event_ids.length - 12} more</span>}
                </div>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </li>
  );
}

function EvidenceDrawer({ id, data, error, onClose }: { id: string; data?: Record<string, unknown>; error?: string; onClose: () => void }) {
  const entries = data ? Object.entries(data).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && !v.length)) : [];
  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end bg-[#1a1a1a33] backdrop-blur-sm" onClick={onClose}>
      <aside onClick={(e) => e.stopPropagation()} className="h-full w-full max-w-xl overflow-y-auto bg-ink-900 p-6 ring-1 ring-line-strong scrollbar-thin rise">
        <div className="flex items-start justify-between gap-4">
          <div><div className="text-[11px] uppercase tracking-[0.12em] text-fg-subtle">Evidence event</div><Mono className="mt-1 block break-all text-sm">{id}</Mono></div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-fg-subtle hover:bg-ink-700 hover:text-fg" aria-label="Close"><X className="size-4" /></button>
        </div>
        {!data && !error && <div className="mt-10 flex items-center gap-2 text-sm text-fg-subtle"><Loader2 className="size-4 animate-spin" />Loading record…</div>}
        {error && <p className="mt-6 rounded-lg bg-crit/10 p-3 text-sm text-crit ring-1 ring-crit/30">{error}</p>}
        {data && (
          <dl className="mt-6 divide-y divide-line rounded-xl ring-1 ring-line">
            {entries.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[150px_1fr] gap-3 px-4 py-2 text-[12px]">
                <dt className="text-fg-subtle break-words">{k}</dt>
                <dd className="font-mono text-fg break-all whitespace-pre-wrap">{typeof v === 'object' ? JSON.stringify(v, null, 1) : String(v)}</dd>
              </div>
            ))}
          </dl>
        )}
      </aside>
    </div>,
    document.body,
  );
}
