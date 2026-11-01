import type { NextConfig } from 'next';
import path from 'node:path';

const config: NextConfig = {
  // Trace runtime dependencies for the small production Docker image.
  output: 'standalone',
  outputFileTracingRoot: path.resolve(__dirname),
  turbopack: { root: path.resolve(__dirname) },
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [{
      source: '/:path*',
      headers: [
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Referrer-Policy', value: 'no-referrer' },
        { key: 'X-Frame-Options', value: 'DENY' },
      ],
    }];
  },
};

export default config;
