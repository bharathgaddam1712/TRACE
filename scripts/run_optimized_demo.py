"""Run the complete local evidence and reachability demo with measured runtime.

python scripts/run_optimized_demo.py --input C:/path/to/events.log
"""
import argparse
import json
import logging
import os
from pathlib import Path
import shutil
import time

import psutil

from tracekc.config import load_config
from tracekc.materialize import write_json
from tracekc.pipeline import run_pipeline
from tracekc.runtime import keep_awake


def main(awake_guard=False):
    local = Path(os.environ.get('LOCALAPPDATA', Path.home()/'.cache'))/'TRACE'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--out', default=str(local/'firex-full-optimized'))
    parser.add_argument('--threads', type=int, default=min(4,psutil.cpu_count() or 4))
    parser.add_argument('--memory', default='1536MB')
    parser.add_argument('--parquet-codec',choices=['zstd','lz4_raw','snappy','uncompressed'],default='zstd')
    args = parser.parse_args()
    output = Path(args.out).resolve();output.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(output).free
    spill_gb = max(1, min(120, int(free*.6/1e9)))
    cfg = load_config(overrides=[f'engine.threads={args.threads}',f'engine.memory_limit={args.memory}',
        f'ingest.parquet_compression={args.parquet_codec}',f'engine.max_temp_directory_size={spill_gb}GB','engine.profile_queries=true',f'engine.blocking_memory_limit={args.memory}'])
    cfg['engine']['temp_directory'] = str(output.parent/'spill')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    available_ram=psutil.virtual_memory().available
    logging.info('Starting full-file run: %s workers, %s DuckDB buffer, %.2f GiB available RAM, %.1f GiB free output disk',
                 args.threads,args.memory,available_ram/2**30,free/2**30)
    started = time.perf_counter();timings={}
    report=run_pipeline(cfg,Path(args.input),output,keep_work=True)
    timings['pipeline_seconds']=report['timings']['total_wall_seconds']
    timings['complete_demo_seconds']=round(time.perf_counter()-started,3)
    timings['under_ten_minutes']=timings['complete_demo_seconds']<600
    timings['under_seven_minutes']=timings['complete_demo_seconds']<420
    timings['awake_request_active']=bool(awake_guard)
    timings['threads']=args.threads;timings['memory_limit']=args.memory
    timings['spill_cap_gb']=spill_gb;timings['source_bytes']=report['ingest']['input_bytes']
    timings['parquet_compression']=args.parquet_codec
    timings['initial_available_ram_bytes']=available_ram;timings['initial_free_disk_bytes']=free
    write_json(output/'demo_timings.json',timings)
    print(json.dumps({'output':str(output),**timings},indent=2))


if __name__=='__main__':
    with keep_awake() as awake:
        main(awake_guard=awake)
