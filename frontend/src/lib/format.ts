export const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });
export const number = new Intl.NumberFormat('en');

export function bytes(n = 0) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function seconds(s = 0) {
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 90) return `${s.toFixed(1)} s`;
  const m = Math.floor(s / 60);
  return m < 90 ? `${m}m ${Math.round(s % 60)}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

export function when(iso?: string) {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';
}

export function duration(from?: string, to?: string) {
  if (!from || !to) return '';
  const ms = new Date(to).getTime() - new Date(from).getTime();
  if (!(ms >= 0)) return '';
  if (ms < 1000) return `${ms} ms`;
  return seconds(ms / 1000);
}

export type Level = 'critical' | 'high' | 'medium' | 'low';
export function severity(value?: number | string): Level {
  if (typeof value === 'string') return (['critical', 'high', 'medium', 'low'].includes(value) ? value : 'low') as Level;
  const v = value ?? 0;
  return v >= 90 ? 'critical' : v >= 70 ? 'high' : v >= 40 ? 'medium' : 'low';
}

export function scoreLevel(score: number): Level {
  return score >= 85 ? 'critical' : score >= 70 ? 'high' : score >= 45 ? 'medium' : 'low';
}

export const LEVEL_COLOR: Record<Level, string> = {
  critical: '#b8432f', high: '#cc7a2e', medium: '#b8952e', low: '#5d8f6a',
};

/** Readable incident title: arrows, and long host chains shortened to the first few hops. */
export function title(text: string, hops = 3) {
  const clean = text.replaceAll(' -> ', ' → ');
  const at = clean.indexOf(' on ');
  if (at < 0) return clean;
  const hosts = clean.slice(at + 4).split(' → ');
  if (hosts.length <= hops + 1) return clean;
  return `${clean.slice(0, at + 4)}${hosts.slice(0, hops).join(' → ')} → … +${hosts.length - hops} more hosts`;
}

export const TACTIC_ORDER = ['Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Stealth', 'Defense Evasion', 'Defense Impairment', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact'];
