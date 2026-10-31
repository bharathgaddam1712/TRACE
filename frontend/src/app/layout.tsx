import type { Metadata } from 'next';
import { Geist, Instrument_Serif, JetBrains_Mono } from 'next/font/google';
import './globals.css';
import { Shell } from '@/components/shell';

const geist = Geist({ subsets: ['latin'], variable: '--font-geist', display: 'swap' });
const serif = Instrument_Serif({ subsets: ['latin'], weight: '400', style: ['normal', 'italic'], variable: '--font-serif-face', display: 'swap' });
const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-mono-face', display: 'swap' });

export const metadata: Metadata = {
  title: { default: 'TRACE · Attack chain intelligence', template: '%s · TRACE' },
  description: 'Reconstruct attack chains from security logs: detection, ATT&CK mapping, correlation, graph and prediction.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geist.variable} ${serif.variable} ${mono.variable}`}>
      <body className="bg-app min-h-screen font-sans">
        <Shell>{children}</Shell>
      </body>
    </html>
  );
}
