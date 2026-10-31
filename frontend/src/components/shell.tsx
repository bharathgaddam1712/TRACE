'use client';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Command, Database, LayoutDashboard, Menu, Search, ShieldCheck, Siren, X } from 'lucide-react';
import { useApi } from '@/lib/api';
import type { AIStatus, Health, IncidentRow, Progress } from '@/lib/types';
import { scoreLevel, LEVEL_COLOR, title as fmtTitle } from '@/lib/format';
import { cx } from './ui';

const NAV = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/incidents', label: 'Incidents', icon: Siren },
  { href: '/coverage', label: 'Detection coverage', icon: ShieldCheck },
  { href: '/data', label: 'Data & pipeline', icon: Database },
];

function Logo() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
        <path d="M16 3.5l10.5 4.6v7c0 6.6-4.5 11.2-10.5 13.2C10 26.3 5.5 21.7 5.5 15.1v-7z" fill="#1a1a1a" />
        <path d="M11.5 16l8.5-3M11.5 16l4.5 5.5M20 13l-4 8.5" stroke="#f0eeea" strokeWidth="1.2" />
        <circle cx="11.5" cy="16" r="2" fill="#f0eeea" /><circle cx="20" cy="13" r="2" fill="#f0eeea" /><circle cx="16" cy="21.5" r="2" fill="#c87840" />
      </svg>
      <span className="font-display text-[26px] leading-none tracking-tight">Trace</span>
    </Link>
  );
}

function StatusPill() {
  const health = useApi<Health>('/health', 15000);
  const ai = useApi<AIStatus>('/ai/status', 60000);
  const progress = useApi<Progress>('/progress', 5000);
  const online = Boolean(health.data) && !health.error;
  const running = progress.data && !['complete', 'idle', 'failed'].includes(progress.data.state);
  const pct = running && progress.data?.source_bytes ? Math.round((100 * (progress.data.completed_bytes ?? 0)) / progress.data.source_bytes) : null;
  return (
    <div className="group relative hidden md:block">
      <button className="flex items-center gap-2 rounded-full px-3 py-2 font-mono text-[11px] text-fg-muted hover:bg-ink-700/70">
        <span className={cx('size-2 rounded-full', online ? 'bg-low live-dot' : 'bg-crit')} />
        {online ? (running ? `running · ${pct ?? 0}%` : 'online') : 'api offline'}
      </button>
      <div className="invisible absolute right-0 top-full z-40 mt-2 w-60 rounded-2xl bg-ink-800 p-4 text-xs opacity-0 shadow-[0_20px_50px_-12px_#0000002e] ring-1 ring-line transition group-hover:visible group-hover:opacity-100">
        <div className="eyebrow mb-3">System status</div>
        {([
          ['API', online ? 'Online' : 'Offline'],
          ['Pipeline', running ? `Running · ${progress.data?.stage}` : progress.data?.state ?? '—'],
          ['Graph engine', health.data?.graph_backend ?? '—'],
          ['Incidents', health.data?.incidents ?? '—'],
          ['Sarvam AI', ai.data ? (ai.data.enabled ? 'Ready' : 'Not configured') : '—'],
        ] as const).map(([k, v]) => (
          <div key={k} className="flex justify-between py-1"><span className="text-fg-subtle">{k}</span><span className="font-mono text-fg-muted">{v}</span></div>
        ))}
      </div>
    </div>
  );
}

function Palette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const { data } = useApi<IncidentRow[]>(open ? '/incidents?limit=1000' : null);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { if (open) { setQ(''); setActive(0); setTimeout(() => input.current?.focus(), 10); } }, [open]);
  const results = useMemo(() => {
    const needle = q.toLowerCase().trim();
    const pages = NAV.filter((n) => !needle || n.label.toLowerCase().includes(needle)).map((n) => ({ kind: 'page' as const, href: n.href, label: n.label, sub: 'Page' }));
    const incidents = (data ?? []).filter((r) => !needle || JSON.stringify([r.id, r.title, r.hosts, r.users, r.tactics, r.entities]).toLowerCase().includes(needle))
      .sort((a, b) => b.score - a.score).slice(0, 8)
      .map((r) => ({ kind: 'incident' as const, href: `/incidents/${r.id}`, label: `#${r.id} · ${fmtTitle(r.title)}`, sub: `${r.score.toFixed(0)} risk · ${(r.tactics ?? []).slice(0, 3).join(', ')}`, score: r.score }));
    return [...pages, ...incidents];
  }, [q, data]);
  if (!open) return null;
  const go = (href: string) => { onClose(); router.push(href); };
  return (
    <div className="fixed inset-0 z-50 grid place-items-start bg-[#1a1a1a33] backdrop-blur-sm pt-[12vh]" onClick={onClose}>
      <div className="mx-auto w-[min(640px,92vw)] panel ring-brand overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search className="size-4 text-fg-subtle" />
          <input ref={input} value={q} onChange={(e) => { setQ(e.target.value); setActive(0); }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(a + 1, results.length - 1)); }
              if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
              if (e.key === 'Enter' && results[active]) go(results[active].href);
              if (e.key === 'Escape') onClose();
            }}
            placeholder="Search incidents, hosts, users, tactics…" className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-fg-subtle" />
          <kbd className="rounded bg-ink-700 px-1.5 py-0.5 text-[10px] text-fg-subtle">ESC</kbd>
        </div>
        <ul className="max-h-[50vh] overflow-y-auto scrollbar-thin p-2">
          {results.length === 0 && <li className="px-3 py-6 text-center text-sm text-fg-subtle">No matches</li>}
          {results.map((r, i) => (
            <li key={r.href}>
              <button onMouseEnter={() => setActive(i)} onClick={() => go(r.href)}
                className={cx('flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left', i === active ? 'bg-ink-600' : 'hover:bg-ink-700')}>
                <span className="size-2 rounded-full shrink-0" style={{ background: r.kind === 'incident' ? LEVEL_COLOR[scoreLevel(r.score)] : '#c87840' }} />
                <span className="min-w-0 flex-1"><span className="block truncate text-sm">{r.label}</span><span className="block truncate text-xs text-fg-subtle">{r.sub}</span></span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function Shell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const [palette, setPalette] = useState(false);
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((p) => !p); } };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  useEffect(() => setMobile(false), [path]);
  const active = (href: string) => (href === '/' ? path === '/' : path.startsWith(href));
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 bg-ink-950/80 backdrop-blur-md">
        <div className="mx-auto flex h-16 w-full max-w-[1480px] items-center gap-4 px-4 sm:px-6 lg:px-8">
          <Logo />
          <nav className="absolute left-1/2 top-0 hidden -translate-x-1/2 rounded-b-[22px] bg-night px-3 pb-2 pt-2.5 shadow-[0_14px_30px_-12px_#00000066] lg:block">
            <ul className="flex items-center gap-1">
              {NAV.map(({ href, label }) => (
                <li key={href}>
                  <Link href={href} className={cx('block rounded-full px-4 py-1.5 text-[13.5px] font-medium transition',
                    active(href) ? 'bg-[#f0eeea] text-[#1a1a1a]' : 'text-[#8a8780] hover:text-[#f0eeea]')}>{label}</Link>
                </li>
              ))}
            </ul>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <StatusPill />
            <button onClick={() => setPalette(true)} className="flex items-center gap-2.5 rounded-full bg-night py-2 pl-4 pr-2 text-[13px] font-medium text-[#f0eeea] transition hover:bg-[#262626]">
              <Search className="size-3.5" /><span className="hidden sm:inline">Search</span>
              <kbd className="hidden items-center gap-0.5 rounded-full bg-[#ffffff1f] px-2 py-0.5 font-mono text-[10px] sm:flex"><Command className="size-2.5" />K</kbd>
            </button>
            <button onClick={() => setMobile((m) => !m)} aria-label="Navigation" className="rounded-full p-2 hover:bg-ink-700 lg:hidden">{mobile ? <X className="size-5" /> : <Menu className="size-5" />}</button>
          </div>
        </div>
        {mobile && (
          <nav className="mx-4 mb-3 rounded-2xl bg-night p-2 lg:hidden">
            {NAV.map(({ href, label, icon: Icon }) => (
              <Link key={href} href={href} className={cx('flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm', active(href) ? 'bg-[#f0eeea] text-[#1a1a1a]' : 'text-[#c9c6bf]')}>
                <Icon className="size-4" />{label}
              </Link>
            ))}
          </nav>
        )}
      </header>
      <main className="relative mx-auto w-full max-w-[1480px] px-4 pb-16 pt-6 sm:px-6 lg:px-8 lg:pt-10">{children}</main>
      <footer className="mx-auto flex w-full max-w-[1480px] flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-8 text-xs text-fg-subtle sm:px-6 lg:px-8">
        <span className="font-display text-lg text-fg">Every incident, explained.</span>
        <span className="font-mono">$ tracekc run → detect → map → link → graph → predict</span>
      </footer>
      <Palette open={palette} onClose={() => setPalette(false)} />
    </div>
  );
}
