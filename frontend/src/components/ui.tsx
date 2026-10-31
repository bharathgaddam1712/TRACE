'use client';
import { Fragment } from 'react';
import { AlertTriangle, Inbox } from 'lucide-react';
import { LEVEL_COLOR, Level, scoreLevel } from '@/lib/format';

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(' ');
}

export function Card({ className, children, hover }: { className?: string; children: React.ReactNode; hover?: boolean }) {
  return <section className={cx('panel', hover && 'panel-hover', className)}>{children}</section>;
}

export function CardHeader({ title, subtitle, icon, action }: { title: string; subtitle?: string; icon?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 px-6 pt-5 pb-4">
      <div className="flex items-start gap-3 min-w-0">
        {icon && <span className="mt-1.5 grid size-7 shrink-0 place-items-center rounded-full bg-ink-700/70 text-fg-muted">{icon}</span>}
        <div className="min-w-0">
          <h3 className="font-display text-[23px] leading-tight tracking-tight text-fg">{title}</h3>
          {subtitle && <p className="text-[13px] text-fg-subtle mt-1 leading-snug">{subtitle}</p>}
        </div>
      </div>
      {action}
    </div>
  );
}

export function LevelBadge({ level, children }: { level: Level; children?: React.ReactNode }) {
  const color = LEVEL_COLOR[level];
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-[0.12em]"
      style={{ color, background: `${color}14`, boxShadow: `inset 0 0 0 1px ${color}33` }}>
      <span className="size-1.5 rounded-full" style={{ background: color }} />{children ?? level}
    </span>
  );
}

export function Chip({ children, tone = 'default', title }: { children: React.ReactNode; tone?: 'default' | 'brand' | 'cyan' | 'muted'; title?: string }) {
  const tones = {
    default: 'bg-ink-800 text-fg-muted ring-line-strong',
    brand: 'bg-brand/10 text-[#9a5626] ring-brand/25',
    cyan: 'bg-brand-2/10 text-brand-2 ring-brand-2/25',
    muted: 'bg-transparent text-fg-subtle ring-line-strong',
  };
  return <span title={title} className={cx('inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] font-medium ring-1 ring-inset whitespace-nowrap', tones[tone])}>{children}</span>;
}

export function ScoreRing({ score, size = 64, stroke = 6, label = true }: { score: number; size?: number; stroke?: number; label?: boolean }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = LEVEL_COLOR[scoreLevel(score)];
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} aria-label={`Risk score ${score.toFixed(0)} of 100`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="#e4e0d9" strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - Math.min(score, 100) / 100)} style={{ transition: 'stroke-dashoffset .8s ease', }} />
      </svg>
      {label && (
        <div className="absolute inset-0 grid place-items-center">
          <span className="font-display tabular-nums" style={{ fontSize: size * 0.36, color }}>{score.toFixed(0)}</span>
        </div>
      )}
    </div>
  );
}

export function Stat({ label, value, hint, icon, accent }: { label: string; value: React.ReactNode; hint?: React.ReactNode; icon?: React.ReactNode; accent?: string }) {
  return (
    <Card hover className="relative overflow-hidden px-5 py-4 rise">
      <div className="absolute right-5 top-5 size-1.5 rounded-full" style={{ background: accent ?? '#c87840' }} />
      <div className="flex items-center justify-between pr-4">
        <span className="eyebrow">{label}</span>
        {icon && <span className="text-fg-subtle">{icon}</span>}
      </div>
      <div className="mt-3 font-display text-[44px] leading-none tracking-tight tabular-nums">{value}</div>
      {hint && <div className="mt-2 text-xs text-fg-subtle">{hint}</div>}
    </Card>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cx('skeleton', className)} />;
}

export function Empty({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
      <Inbox className="size-8 text-fg-subtle" strokeWidth={1.5} />
      <p className="text-sm font-medium text-fg-muted">{title}</p>
      {children && <div className="max-w-md text-xs text-fg-subtle">{children}</div>}
    </div>
  );
}

export function ErrorBox({ error }: { error: { message: string; status?: number } }) {
  return (
    <Card className="p-6">
      <div className="flex gap-3">
        <AlertTriangle className="size-5 text-crit shrink-0" />
        <div>
          <p className="text-sm font-semibold">Could not load data</p>
          <p className="text-sm text-fg-muted mt-1">{error.message}</p>
        </div>
      </div>
    </Card>
  );
}

export function Button({ children, onClick, variant = 'secondary', disabled, type = 'button', className, title }: {
  children: React.ReactNode; onClick?: () => void; variant?: 'primary' | 'secondary' | 'ghost'; disabled?: boolean;
  type?: 'button' | 'submit'; className?: string; title?: string;
}) {
  const variants = {
    primary: 'bg-night text-[#f0eeea] hover:bg-[#2a2a2a]',
    secondary: 'bg-ink-800 text-fg ring-1 ring-inset ring-line-strong hover:bg-ink-700',
    ghost: 'text-fg-muted hover:text-fg hover:bg-ink-700/60',
  };
  return (
    <button type={type} onClick={onClick} disabled={disabled} title={title}
      className={cx('inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-full px-4 py-2 text-[13px] font-medium transition disabled:opacity-40 disabled:cursor-not-allowed focus-visible:outline-2 focus-visible:outline-brand', variants[variant], className)}>
      {children}
    </button>
  );
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { id: T; label: string; icon?: React.ReactNode; count?: number }[] }) {
  return (
    <div role="tablist" className="inline-flex max-w-full gap-1 overflow-x-auto scrollbar-thin rounded-full bg-ink-700/60 p-1">
      {items.map((item) => (
        <button key={item.id} role="tab" aria-selected={value === item.id} onClick={() => onChange(item.id)}
          className={cx('flex items-center gap-2 whitespace-nowrap rounded-full px-4 py-2 text-[13px] font-medium transition',
            value === item.id ? 'bg-night text-[#f0eeea] shadow-[0_6px_16px_-8px_#00000080]' : 'text-fg-muted hover:text-fg')}>
          {item.icon}{item.label}
          {item.count !== undefined && <span className={cx('rounded-full px-1.5 font-mono text-[10.5px] tabular-nums', value === item.id ? 'bg-[#ffffff22] text-[#d9d6cf]' : 'bg-ink-800 text-fg-subtle')}>{item.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Bars({ rows, color = '#c87840', format = (v: number) => v.toLocaleString(), max }: {
  rows: { label: string; value: number; hint?: string; color?: string }[]; color?: string; format?: (v: number) => string; max?: number;
}) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="space-y-2.5">
      {rows.map((row) => (
        <div key={row.label} className="group">
          <div className="flex items-baseline justify-between gap-3 text-xs">
            <span className="truncate text-fg-muted group-hover:text-fg" title={row.label}>{row.label}</span>
            <span className="tabular-nums text-fg font-medium">{format(row.value)}</span>
          </div>
          <div className="mt-1.5 h-1.5 rounded-full bg-ink-700 overflow-hidden">
            <div className="h-full rounded-full transition-[width] duration-700" style={{ width: `${(row.value / top) * 100}%`, background: row.color ?? color }} />
          </div>
        </div>
      ))}
    </div>
  );
}

export function KV({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,auto)_1fr] gap-x-4 gap-y-2 text-[13px]">
      {rows.map(([k, v]) => (<Fragment key={k}><dt className="text-fg-subtle">{k}</dt><dd className="text-fg min-w-0 break-words">{v}</dd></Fragment>))}
    </dl>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cx('font-mono text-[12px]', className)}>{children}</span>;
}
