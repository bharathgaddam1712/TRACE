"""Plan or execute fresh engine trials; never select an unmeasured default.

Example: python scripts/sweep_engine.py --input C:/logs/new.log --out out/sweep
Add --execute to run the plan. Close other heavy applications first.
"""
import argparse
import csv
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import psutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--threads', type=int, nargs='+', default=[4, 8, 10])
    parser.add_argument('--memory-gb', type=int, nargs='+', default=[2, 6, 8])
    parser.add_argument('--blocking-threads', type=int, nargs='+', default=[4, 8])
    parser.add_argument('--peak-limit-gb', type=float, default=8)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--trial', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.input.exists(): parser.error('Input does not exist')
    if args.input.is_dir() and args.out.resolve().is_relative_to(args.input.resolve()):
        parser.error('Output must be outside the input directory')
    if (any(n < 1 or n > 256 for n in args.threads + args.blocking_threads)
            or any(n < 1 for n in args.memory_gb) or args.peak_limit_gb <= 0):
        parser.error('Invalid resource limit')
    if args.trial:
        from tracekc.config import load_config
        from tracekc.pipeline import run_pipeline
        cfg = load_config(overrides=[f'engine.threads={args.threads[0]}',
            f'engine.memory_limit={args.memory_gb[0]}GB',
            f'engine.blocking_threads={args.blocking_threads[0]}',
            f'engine.blocking_memory_limit={args.memory_gb[0]}GB','engine.profile_queries=true'])
        run_pipeline(cfg, args.input, args.trial, keep_work=True)
        return
    combinations = sorted(set((t, m, min(t, b)) for t, m, b in itertools.product(
        args.threads, args.memory_gb, args.blocking_threads)))
    print(json.dumps({'plan': combinations, 'columns': ['threads', 'memory_gb', 'blocking_threads'],
        'execute': args.execute, 'available_gib': round(psutil.virtual_memory().available / 2**30, 2)}, indent=2))
    if not args.execute: return
    # Exclusive creation prevents accidentally overwriting a previous rehearsal.
    args.out.mkdir(parents=True, exist_ok=False)
    source_bytes = (args.input.stat().st_size if args.input.is_file() else
        sum(p.stat().st_size for p in args.input.rglob('*') if p.is_file()))
    columns = ['threads', 'memory_gb', 'blocking_threads', 'status', 'wall_seconds',
        'peak_tree_rss_bytes', 'pipeline_peak_rss_bytes', 'events', 'incidents', 'stage_timings', 'stage_peak_rss']
    with (args.out / 'sweep.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns); writer.writeheader()
        for t, m, b in combinations:
            row = dict(threads=t, memory_gb=m, blocking_threads=b)
            # Leave headroom for non-buffer allocations, OS and the UI.
            if shutil.disk_usage(args.out).free < source_bytes * 3 + 2**30:
                row['status'] = 'skipped_disk_headroom'
            elif psutil.virtual_memory().available < (m + 1) * 2**30 or m >= args.peak_limit_gb:
                row['status'] = 'skipped_resource_headroom'
            else:
                trial = args.out / f't{t}-m{m}-b{b}'
                command = [sys.executable, str(Path(__file__).resolve()), '--input', str(args.input.resolve()),
                    '--out', str(args.out.resolve()), '--trial', str(trial.resolve()),
                    '--threads', str(t), '--memory-gb', str(m), '--blocking-threads', str(b)]
                start = time.perf_counter(); peak = 0; exceeded = False
                with (args.out / (trial.name + '.log')).open('w', encoding='utf-8') as log:
                    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                    owned = psutil.Process(process.pid)
                    while process.poll() is None:
                        try:
                            members = [owned, *owned.children(recursive=True)]
                            rss = sum(p.memory_info().rss for p in members if p.is_running())
                            peak = max(peak, rss)
                            if rss > args.peak_limit_gb * 2**30:
                                exceeded = True
                                for member in reversed(members):
                                    try: member.terminate()
                                    except psutil.NoSuchProcess: pass
                                break
                        except psutil.NoSuchProcess: pass
                        time.sleep(.1)
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()
                row.update(status='memory_rejected' if exceeded else ('ok' if process.returncode == 0 else 'failed'),
                    wall_seconds=round(time.perf_counter() - start, 3), peak_tree_rss_bytes=peak)
                report_path = trial / 'run_metrics.json'
                if report_path.exists() and row['status'] == 'ok':
                    report = json.loads(report_path.read_text(encoding='utf-8'))
                    row.update(events=report.get('ingest', {}).get('events'),
                        incidents=report.get('output', {}).get('incidents'),
                        pipeline_peak_rss_bytes=report.get('peak_process_tree_rss_bytes'),
                        stage_peak_rss=json.dumps(report.get('stage_peak_process_tree_rss_bytes', {})),
                        stage_timings=json.dumps(report.get('timings', {})))
            writer.writerow(row); stream.flush()
    print('Counts are diagnostics, not proof of result equivalence. Compare full outputs before choosing a default.')


if __name__ == '__main__':
    main()
