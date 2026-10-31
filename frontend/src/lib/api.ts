'use client';
import { useCallback, useEffect, useRef, useState } from 'react';

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

export async function api<T>(path: string, init?: { method?: 'GET' | 'POST'; body?: unknown }): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method: init?.method ?? 'GET',
    headers: init?.body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: 'no-store',
  });
  const text = await response.text();
  let data: unknown = text;
  try { data = text ? JSON.parse(text) : null; } catch { /* plain text, e.g. report */ }
  if (!response.ok) {
    const detail = (data as { detail?: unknown })?.detail;
    throw new ApiError(response.status, typeof detail === 'string' ? detail : `Request failed (${response.status})`);
  }
  return data as T;
}

export function useApi<T>(path: string | null, refreshMs?: number) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<ApiError | undefined>();
  const [loading, setLoading] = useState(Boolean(path));
  const current = useRef(path);
  current.current = path;

  const load = useCallback(async () => {
    if (!path) return;
    try {
      const result = await api<T>(path);
      if (current.current === path) { setData(result); setError(undefined); }
    } catch (e) {
      if (current.current === path) setError(e instanceof ApiError ? e : new ApiError(0, String(e)));
    } finally {
      if (current.current === path) setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    setLoading(Boolean(path));
    load();
    if (!refreshMs || !path) return;
    const timer = setInterval(load, refreshMs);
    return () => clearInterval(timer);
  }, [path, refreshMs, load]);

  return { data, error, loading, reload: load, setData };
}
