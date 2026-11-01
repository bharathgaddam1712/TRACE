"""Run the complete local demo, including measured forecast fit and attachment.

python scripts/run_optimized_demo.py --input C:/path/to/events.log
"""
import argparse
import json
import logging
import os
from pathlib import Path
import shutil
import time
import subprocess
import sys

import psutil

from tracekc.config import load_config
from tracekc.forecast import automatic_cutoffs, attach_model, benchmark, export_history
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
    parser.add_argument('--temporal-events', type=int, default=100000,
                        help='Bounded optional network ML experiment; 0 disables. Core pipeline reads the full file.')
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
    started = time.perf_counter();timings={};worker=None
    def start_temporal(events):
        nonlocal worker
        if not args.temporal_events:return
        env=os.environ.copy()
        for name in ('OMP_NUM_THREADS','MKL_NUM_THREADS','OPENBLAS_NUM_THREADS'):env[name]='1'
        with (output/'temporal-worker.log').open('wb') as log:
            worker=subprocess.Popen([sys.executable,'-m','tracekc','temporal-benchmark','--events',str(events),
                '--out',str(output),'--max-events',str(args.temporal_events)],stdout=log,stderr=subprocess.STDOUT,
                env=env,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    try:
        report=run_pipeline(cfg,Path(args.input),output,keep_work=True,on_ingested=start_temporal)
    except BaseException:
        if worker is not None and worker.poll() is None:
            parent=psutil.Process(worker.pid)
            for child in parent.children(recursive=True):child.terminate()
            parent.terminate()
        raise
    timings['pipeline_seconds']=report['timings']['total_wall_seconds']
    stage=time.perf_counter();history=export_history(output,use_cache=True)
    write_json(output/'histories.json',history)
    timings['history_export_seconds']=round(time.perf_counter()-stage,3)
    try:
        stage=time.perf_counter()
        left,right=automatic_cutoffs(history['incidents'])
        comparison,model,_=benchmark(output/'histories.json',left,right)
        timings['forecast_fit_and_evaluate_seconds']=round(time.perf_counter()-stage,3)
        write_json(output/'forecast-comparison.json',comparison)
        write_json(output/'forecast-model.json',model)
        stage=time.perf_counter();attach_model(output,output/'forecast-model.json',sidecar=True)
        timings['forecast_attachment_seconds']=round(time.perf_counter()-stage,3)
    except ValueError as exc:
        timings['forecast_status']=f'unavailable: {exc}'
    if worker is not None:
        stage=time.perf_counter()
        if worker.wait()!=0:raise RuntimeError('Temporal experiment failed; inspect '+str(output/'temporal-worker.log'))
        timings['temporal_wait_after_pipeline_seconds']=round(time.perf_counter()-stage,3)
        temporal_report=json.loads((output/'temporal-benchmark.json').read_text())
        timings['temporal_experiment_seconds']=temporal_report['seconds']
        timings['temporal_status']=temporal_report.get('status','complete')
        timings['temporal_experiment_parallel']=True
    timings['complete_demo_seconds']=round(time.perf_counter()-started,3)
    timings['under_ten_minutes']=timings['complete_demo_seconds']<600
    timings['under_seven_minutes']=timings['complete_demo_seconds']<420
    timings['awake_request_active']=bool(awake_guard)
    timings['threads']=args.threads;timings['memory_limit']=args.memory
    timings['spill_cap_gb']=spill_gb;timings['source_bytes']=Path(args.input).stat().st_size
    timings['parquet_compression']=args.parquet_codec
    timings['initial_available_ram_bytes']=available_ram;timings['initial_free_disk_bytes']=free
    write_json(output/'demo_timings.json',timings)
    print(json.dumps({'output':str(output),**timings},indent=2))


if __name__=='__main__':
    with keep_awake() as awake:
        main(awake_guard=awake)
