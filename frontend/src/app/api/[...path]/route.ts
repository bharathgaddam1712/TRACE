// Server-side proxy to the TRACE FastAPI service. The browser never sees the API token, and
// server-to-server requests carry no Origin header, so the API's cross-origin write guard holds.
import { NextRequest } from 'next/server';

const API = (process.env.TRACE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const TOKEN = process.env.TRACE_API_TOKEN || '';
const PATH = /^[A-Za-z0-9._~:@%-]+$/;

async function forward(request: NextRequest, params: Promise<{ path: string[] }>) {
  const { path } = await params;
  if (!path.every((part) => PATH.test(part))) {
    return Response.json({ detail: 'Invalid path' }, { status: 400 });
  }
  const url = `${API}/${path.map(encodeURIComponent).join('/')}${request.nextUrl.search}`;
  const headers: Record<string, string> = { accept: request.headers.get('accept') || 'application/json' };
  if (TOKEN) headers.authorization = `Bearer ${TOKEN}`;
  let body: string | undefined;
  if (request.method === 'POST') {
    headers['content-type'] = 'application/json';
    body = await request.text();
  }
  try {
    const upstream = await fetch(url, { method: request.method, headers, body, cache: 'no-store' });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: { 'content-type': upstream.headers.get('content-type') || 'application/json', 'cache-control': 'no-store' },
    });
  } catch {
    return Response.json({ detail: `TRACE API unreachable at ${API}. Start it with: python -m tracekc serve --out OUT` }, { status: 502 });
  }
}

export async function GET(request: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return forward(request, ctx.params);
}

export async function POST(request: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return forward(request, ctx.params);
}
