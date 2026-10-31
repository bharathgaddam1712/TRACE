'use client';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { use, useState } from 'react';
import { ArrowLeft, BookOpen, Clock, Layers, Link2, Network, Radar, ShieldAlert, Users } from 'lucide-react';
import { useApi } from '@/lib/api';
import type { AIStatus, Incident } from '@/lib/types';
import { duration, number, scoreLevel, title, when } from '@/lib/format';
import { Card, CardHeader, Chip, ErrorBox, LevelBadge, ScoreRing, Skeleton, Tabs } from '@/components/ui';
import { Narrative, Timeline } from '@/components/incident/Story';
import { Lookahead, NextTechnique } from '@/components/incident/Predict';
import { AskPanel, CasePanel, Downloads, TriagePanel } from '@/components/incident/Respond';
import { PathFinder } from '@/components/incident/PathFinder';

const GraphExplorer = dynamic(() => import('@/components/graph/GraphExplorer'), {
  ssr: false, loading: () => <Skeleton className="h-[640px] w-full" />,
});

type Tab = 'story' | 'graph' | 'predict' | 'respond';

export default function IncidentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data: inc, error, setData } = useApi<Incident>(`/incidents/${id}`);
  const { data: ai } = useApi<AIStatus>('/ai/status');
  const [tab, setTab] = useState<Tab>('story');
  const [path, setPath] = useState<string[]>([]);
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');

  if (error) return <div className="space-y-4"><Back /><ErrorBox error={error} /></div>;
  if (!inc) return <div className="space-y-4"><Back /><Skeleton className="h-40" /><Skeleton className="h-12" /><Skeleton className="h-96" /></div>;

  const level = scoreLevel(inc.score);
  const ents = inc.entities ?? {};
  const pick = (n: string) => { if (!source || (source && target)) { setSource(n); setTarget(''); } else setTarget(n); };

  return (
    <div className="space-y-5">
      <Back />
      <Card className="relative overflow-hidden rise">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,rgba(200,120,64,.16),transparent_55%)]" />
        <div className="relative flex flex-col gap-5 p-6 md:flex-row md:items-center">
          <ScoreRing score={inc.score} size={92} stroke={8} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <LevelBadge level={level} /><span className="font-mono text-xs text-fg-subtle">INC-{String(inc.id).padStart(4, '0')}</span>
              <Chip tone="muted">case: {inc.case.status}</Chip>
            </div>
            <h1 className="mt-3 font-display text-[34px] leading-[1.05] tracking-tight md:text-[44px]">{title(inc.title)}</h1>
            {inc.score_interpretation && <p className="mt-1 text-sm text-fg-muted">{inc.score_interpretation}</p>}
            <div className="mt-3 flex flex-wrap gap-1.5">{inc.tactics.map((t) => <Chip key={t} tone="brand">{t}</Chip>)}</div>
          </div>
        </div>
        <div className="relative grid grid-cols-2 border-t border-line md:grid-cols-5">
          <Fact icon={<Clock className="size-3.5" />} k="Window" v={duration(inc.first_seen, inc.last_seen)} sub={when(inc.first_seen)} />
          <Fact icon={<Layers className="size-3.5" />} k="Steps" v={inc.timeline.length} sub={`${number.format(inc.raw_event_count ?? 0)} raw events`} />
          <Fact icon={<ShieldAlert className="size-3.5" />} k="Hosts" v={ents.hosts?.length ?? 0} sub={ents.hosts?.slice(0, 2).join(', ')} />
          <Fact icon={<Users className="size-3.5" />} k="Users" v={ents.users?.length ?? 0} sub={ents.users?.slice(0, 2).join(', ')} />
          <Fact icon={<Radar className="size-3.5" />} k="Reachable next" v={inc.lookahead.reachable.length} sub="assets with observed access" />
        </div>
      </Card>

      <div className="sticky top-0 z-20 -mx-1 bg-ink-950/80 px-1 py-2 backdrop-blur">
        <Tabs value={tab} onChange={setTab} items={[
          { id: 'story', label: 'Story', icon: <BookOpen className="size-4" />, count: inc.timeline.length },
          { id: 'graph', label: 'Attack graph', icon: <Network className="size-4" />, count: inc.graph.nodes.length },
          { id: 'predict', label: 'Predict', icon: <Radar className="size-4" />, count: inc.lookahead.reachable.length },
          { id: 'respond', label: 'Respond', icon: <ShieldAlert className="size-4" /> },
        ]} />
      </div>

      {tab === 'story' && (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_380px] rise">
          <Timeline incident={inc} />
          <div className="space-y-5">
            {inc.host_path_text && <Card><CardHeader title="Host path" subtitle="Order the attacker touched hosts" /><p className="px-5 pb-5 font-mono text-xs leading-relaxed text-brand-2">{inc.host_path_text}</p></Card>}
            <Narrative text={inc.narrative} />
            <Related incident={inc} />
          </div>
        </div>
      )}
      {tab === 'graph' && (
        <div className="space-y-4 rise">
          <Card className="p-5"><PathFinder incidentId={inc.id} graph={inc.graph} source={source} target={target} setSource={setSource} setTarget={setTarget} onPath={setPath} /></Card>
          <Card className="p-4"><GraphExplorer graph={inc.graph} path={path} onPick={pick} /></Card>
        </div>
      )}
      {tab === 'predict' && <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_420px] rise"><Lookahead incident={inc} /><NextTechnique incident={inc} /></div>}
      {tab === 'respond' && (
        <div className="grid gap-5 xl:grid-cols-2 rise">
          <div className="space-y-5"><TriagePanel incident={inc} ai={ai} /><AskPanel incident={inc} ai={ai} /></div>
          <div className="space-y-5"><CasePanel incident={inc} onChange={(c) => setData({ ...inc, case: c })} /><Downloads incident={inc} /></div>
        </div>
      )}
    </div>
  );
}

function Back() {
  return <Link href="/incidents" className="inline-flex items-center gap-1.5 text-xs text-fg-subtle hover:text-fg"><ArrowLeft className="size-3.5" />All incidents</Link>;
}

function Fact({ icon, k, v, sub }: { icon: React.ReactNode; k: string; v: React.ReactNode; sub?: string }) {
  return (
    <div className="border-line px-5 py-3.5 [&:not(:last-child)]:border-r">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-[0.12em] text-fg-subtle">{icon}{k}</div>
      <div className="mt-1 text-lg font-semibold tabular-nums">{v}</div>
      {sub && <div className="truncate text-[11px] text-fg-subtle">{sub}</div>}
    </div>
  );
}

function Related({ incident }: { incident: Incident }) {
  const rel = incident.related_incidents ?? [];
  if (!rel.length) return null;
  return (
    <Card>
      <CardHeader icon={<Link2 className="size-4" />} title="Related incidents" subtitle="Shared hosts, users or infrastructure" />
      <ul className="px-5 pb-5 space-y-1.5">
        {rel.slice(0, 8).map((r) => {
          const other = r.source === incident.id ? r.target : r.source;
          return (
            <li key={other}><Link href={`/incidents/${other}`} className="flex items-center justify-between rounded-lg px-3 py-2 ring-1 ring-line hover:ring-brand/50 hover:bg-ink-700/40">
              <span className="font-mono text-xs">INC-{String(other).padStart(4, '0')}</span>
              <span className="text-xs text-fg-subtle">similarity {(r.score * 100).toFixed(0)}%</span>
            </Link></li>
          );
        })}
      </ul>
    </Card>
  );
}
