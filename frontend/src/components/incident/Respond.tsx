'use client';
import { useState } from 'react';
import { Bot, CheckCircle2, Download, Languages, Loader2, MessageSquare, ShieldCheck } from 'lucide-react';
import { api, useApi } from '@/lib/api';
import type { AIStatus, CaseInfo, CaseStatus, Incident, TriageResult } from '@/lib/types';
import { when } from '@/lib/format';
import { Button, Card, CardHeader, Chip, Empty, Mono, cx } from '@/components/ui';

const STATUSES: { id: CaseStatus; label: string; color: string }[] = [
  { id: 'new', label: 'New', color: '#c87840' }, { id: 'investigating', label: 'Investigating', color: '#c9902f' },
  { id: 'contained', label: 'Contained', color: '#3f7f7a' }, { id: 'closed', label: 'Closed', color: '#5d8f6a' },
];
const LANGUAGES = ['English', 'Hindi', 'Telugu', 'Tamil', 'Kannada', 'Malayalam', 'Marathi', 'Bengali', 'Gujarati', 'Punjabi', 'Odia'];
const base = 'rounded-lg bg-ink-900 px-3 py-2 text-[13px] ring-1 ring-line outline-none placeholder:text-fg-subtle focus:ring-brand/60';
const field = `w-full ${base}`;

export function CasePanel({ incident, onChange }: { incident: Incident; onChange: (c: CaseInfo) => void }) {
  const c = incident.case;
  const [status, setStatus] = useState<CaseStatus>(c.status);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      const next = await api<CaseInfo>(`/incidents/${incident.id}/case`, { method: 'POST', body: { status, note, version: c.version } });
      onChange(next); setNote(''); setMsg({ ok: true, text: 'Case updated' });
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }); } finally { setBusy(false); }
  };
  return (
    <Card>
      <CardHeader icon={<ShieldCheck className="size-4" />} title="Case" subtitle={`Version ${c.version} · changes are audited`} />
      <div className="px-5 pb-5 space-y-3">
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
          {STATUSES.map((s) => (
            <button key={s.id} onClick={() => setStatus(s.id)} className={cx('rounded-lg px-2 py-2 text-xs font-medium ring-1 transition', status === s.id ? 'text-fg' : 'text-fg-muted ring-line hover:ring-line-strong')}
              style={status === s.id ? { background: `${s.color}1f`, boxShadow: `inset 0 0 0 1px ${s.color}80` } : undefined}>{s.label}</button>
          ))}
        </div>
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Analyst note (what you checked, why you changed the status)…" className={field} />
        <div className="flex items-center gap-3">
          <Button variant="primary" onClick={save} disabled={busy || (status === c.status && !note.trim())}>{busy && <Loader2 className="size-3.5 animate-spin" />}Save case</Button>
          {msg && <span className={cx('text-xs', msg.ok ? 'text-low' : 'text-crit')}>{msg.text}</span>}
        </div>
        {c.history.length > 0 && (
          <ol className="mt-2 space-y-2 border-l border-line pl-4">
            {[...c.history].reverse().slice(0, 6).map((h, i) => (
              <li key={i} className="text-xs"><span className="font-medium text-fg capitalize">{h.status}</span> <span className="text-fg-subtle">· {when(h.ts)}</span>{h.note && <p className="mt-0.5 text-fg-muted">{h.note}</p>}</li>
            ))}
          </ol>
        )}
      </div>
    </Card>
  );
}

export function TriagePanel({ incident, ai }: { incident: Incident; ai?: AIStatus }) {
  const latest = useApi<{ result: TriageResult | null; reviews: { decision: string; note: string; ts?: string }[] }>(`/incidents/${incident.id}/triage`);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [decision, setDecision] = useState('escalate');
  const [note, setNote] = useState('');
  const result = latest.data?.result;
  const run = async () => {
    setBusy(true); setErr('');
    try { const r = await api<TriageResult>(`/incidents/${incident.id}/triage`, { method: 'POST', body: { investigate: false } }); latest.setData({ result: r, reviews: latest.data?.reviews ?? [] }); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const review = async () => {
    if (!result) return;
    setErr('');
    try { latest.setData(await api(`/incidents/${incident.id}/triage/review`, { method: 'POST', body: { context_hash: result.context_hash, decision, note } })); setNote(''); }
    catch (e) { setErr((e as Error).message); }
  };
  const v = result?.verdict;
  const tone = v?.assessment === 'attack_suspected' ? '#b8432f' : v?.assessment === 'likely_benign' ? '#5d8f6a' : '#c9902f';
  return (
    <Card>
      <CardHeader icon={<Bot className="size-4" />} title="AI triage agent" subtitle="Advisory verdict with cited evidence — an analyst always makes the final call"
        action={<Button variant="primary" onClick={run} disabled={busy}>{busy ? <Loader2 className="size-3.5 animate-spin" /> : <Bot className="size-3.5" />}{result ? 'Re-run' : 'Run triage'}</Button>} />
      <div className="px-5 pb-5 space-y-4">
        {!ai?.enabled && <p className="rounded-lg bg-med/10 px-3 py-2 text-xs text-med ring-1 ring-med/25">No AI provider key configured — triage will return <Mono>insufficient_evidence</Mono> and keep the case open. Set <Mono>SARVAM_API_KEY</Mono> on the API server to enable it.</p>}
        {err && <p className="text-xs text-crit">{err}</p>}
        {!v ? <Empty title="No triage run yet">Run the agent to get a P1–P3 priority, rationale, contradicting evidence and next checks.</Empty> : (
          <div className="space-y-4 rise">
            <div className="flex flex-wrap items-center gap-2">
              <span className="rounded-md px-2.5 py-1 text-xs font-semibold" style={{ color: tone, background: `${tone}1a`, boxShadow: `inset 0 0 0 1px ${tone}55` }}>{v.assessment.replace(/_/g, ' ')}</span>
              <Chip>{v.priority}</Chip><Chip>{v.severity}</Chip><Chip tone="muted">{result!.status.replace(/_/g, ' ').toLowerCase()}</Chip>
            </div>
            <p className="text-[13px] leading-relaxed text-fg-muted">{v.rationale}</p>
            <div className="grid gap-3 sm:grid-cols-3">
              {([['Contradicting', v.contradictory_evidence], ['Missing', v.missing_evidence], ['Next checks', v.next_checks]] as const).map(([k, list]) => (
                <div key={k} className="rounded-lg bg-ink-900/60 p-3 ring-1 ring-line">
                  <div className="text-[11px] uppercase tracking-[0.12em] text-fg-subtle">{k}</div>
                  <ul className="mt-1.5 space-y-1 text-xs text-fg-muted">{list.length ? list.map((x, i) => <li key={i}>• {x}</li>) : <li className="text-fg-subtle">—</li>}</ul>
                </div>
              ))}
            </div>
            {result!.errors?.length ? <p className="text-xs text-med">{result!.errors.join(' · ')}</p> : null}
            <div className="rounded-lg bg-ink-900/60 p-3 ring-1 ring-line space-y-2">
              <div className="text-[11px] uppercase tracking-[0.12em] text-fg-subtle">Analyst review</div>
              <div className="flex flex-wrap gap-2">
                <select value={decision} onChange={(e) => setDecision(e.target.value)} className={base}>
                  <option value="escalate">Escalate</option><option value="monitor">Monitor</option><option value="likely_benign">Likely benign</option>
                </select>
                <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Review note (required)" className={cx(base, 'flex-1 min-w-48')} />
                <Button onClick={review} disabled={!note.trim()}><CheckCircle2 className="size-3.5" />Record</Button>
              </div>
              {latest.data?.reviews?.map((r, i) => <div key={i} className="text-xs text-fg-muted"><span className="font-medium text-fg">{r.decision}</span> — {r.note}</div>)}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

type Answer = { answer?: string; citations?: string[]; next_checks?: string[]; hypotheses?: unknown[]; cached?: boolean };
export function AskPanel({ incident, ai }: { incident: Incident; ai?: AIStatus }) {
  const [task, setTask] = useState('summary');
  const [question, setQuestion] = useState('');
  const [language, setLanguage] = useState('English');
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<Answer | null>(null);
  const [err, setErr] = useState('');
  const ask = async () => {
    setBusy(true); setErr('');
    try { setOut(await api<Answer>(`/incidents/${incident.id}/ai`, { method: 'POST', body: { task, question, language } })); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Card>
      <CardHeader icon={<MessageSquare className="size-4" />} title="Ask about this incident" subtitle={ai?.enabled ? `${ai.model} · ${ai.requests_today}/${ai.daily_request_limit} requests today` : 'AI assistant is off — set SARVAM_API_KEY to enable'} />
      <div className="px-5 pb-5 space-y-3">
        <div className="flex flex-wrap gap-2">
          <select value={task} onChange={(e) => setTask(e.target.value)} className={base} disabled={!ai?.enabled}>
            <option value="summary">Summarize</option><option value="chat">Question</option><option value="investigate">Investigate</option><option value="map">Suggest mappings</option><option value="rule">Draft Sigma rule</option><option value="translate">Translate</option>
          </select>
          <label className="relative"><Languages className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" />
            <select value={language} onChange={(e) => setLanguage(e.target.value)} className={cx(base, 'pl-8')} disabled={!ai?.enabled}>{LANGUAGES.map((l) => <option key={l}>{l}</option>)}</select></label>
        </div>
        <textarea value={question} onChange={(e) => setQuestion(e.target.value)} rows={2} maxLength={2000} disabled={!ai?.enabled} className={field}
          placeholder="e.g. Which account should be disabled first, and why?" />
        <Button variant="primary" onClick={ask} disabled={!ai?.enabled || busy}>{busy && <Loader2 className="size-3.5 animate-spin" />}Ask</Button>
        {err && <p className="text-xs text-crit">{err}</p>}
        {out && (
          <div className="rounded-lg bg-ink-900/60 p-4 ring-1 ring-line space-y-2 rise">
            <p className="whitespace-pre-wrap text-[13px] leading-relaxed">{out.answer}</p>
            {out.next_checks?.length ? <ul className="text-xs text-fg-muted">{out.next_checks.map((x, i) => <li key={i}>• {x}</li>)}</ul> : null}
            {out.citations?.length ? <div className="flex flex-wrap gap-1">{out.citations.map((c) => <Chip key={c} tone="muted">{c.slice(0, 12)}…</Chip>)}</div> : null}
          </div>
        )}
      </div>
    </Card>
  );
}

export function Downloads({ incident }: { incident: Incident }) {
  const save = (name: string, body: string, type: string) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([body], { type }));
    a.download = name; a.click(); URL.revokeObjectURL(a.href);
  };
  const report = async () => save(`trace-incident-${incident.id}.md`, await api<string>(`/incidents/${incident.id}/report`), 'text/markdown');
  return (
    <Card>
      <CardHeader icon={<Download className="size-4" />} title="Export" subtitle="Hand off to ticketing or IR" />
      <div className="flex flex-wrap gap-2 px-5 pb-5">
        <Button onClick={report}><Download className="size-3.5" />Report (.md)</Button>
        <Button onClick={() => save(`trace-incident-${incident.id}.json`, JSON.stringify(incident, null, 2), 'application/json')}><Download className="size-3.5" />Incident (.json)</Button>
      </div>
    </Card>
  );
}
