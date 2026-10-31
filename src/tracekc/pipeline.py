"""Stage orchestration with per-stage timings and peak process-tree RSS (benchmark protocol)."""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import shutil
import threading
import time
import os
from contextlib import contextmanager
from pathlib import Path

import psutil
import yaml

from tracekc import __version__
from tracekc.config import project_path
from tracekc.correlate import assemble, build_signals, link_edges, record_assignment
from tracekc.detect import detect
from tracekc.engine import connect, finish_query_profile, one, run
from tracekc.ingest import ingest
from tracekc.label import label, load_mapping
from tracekc.materialize import materialize, write_json
from tracekc.reach import AccessGraph
from tracekc.sigma import load_rules, lit

log = logging.getLogger(__name__)


class RssSampler(threading.Thread):
    """Samples RSS of this process plus children every interval; .peak is the maximum seen."""

    def __init__(self, interval: float = 0.5):
        super().__init__(daemon=True)
        self.interval, self.peak, self._stop_evt = interval, 0, threading.Event()
        self.proc = psutil.Process()

    def _rss(self) -> int:
        total = self.proc.memory_info().rss
        for child in self.proc.children(recursive=True):
            try:
                total += child.memory_info().rss
            except psutil.Error:
                pass
        return total

    def run(self) -> None:
        while not self._stop_evt.is_set():
            self.peak = max(self.peak, self._rss())
            self._stop_evt.wait(self.interval)

    def stop(self) -> int:
        self.peak = max(self.peak, self._rss())
        self._stop_evt.set()
        return self.peak


def _hash_dir(path: Path, pattern: str) -> str:
    h = hashlib.sha256()
    for f in sorted(path.rglob(pattern)):
        h.update(f.name.encode())
        h.update(f.read_bytes())
    return h.hexdigest()[:16]


def run_pipeline(cfg: dict, input_dir: Path, out_dir: Path, keep_work: bool = False, on_ingested=None) -> dict:
    input_dir, out_dir = input_dir.resolve(), out_dir.resolve()
    if input_dir.is_dir() and out_dir.is_relative_to(input_dir):
        raise ValueError('Output must be outside the input directory to avoid ingesting generated files')
    out_dir.mkdir(parents=True, exist_ok=True)
    lock = out_dir / '.pipeline.lock'
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise ValueError(f'Output is locked by another run. If no pipeline is running, remove {lock}') from None
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(str(os.getpid()))
        return _run_pipeline(cfg, input_dir, out_dir, keep_work, on_ingested)
    finally:
        lock.unlink(missing_ok=True)


def _run_pipeline(cfg: dict, input_dir: Path, out_dir: Path, keep_work: bool = False, on_ingested=None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    work = out_dir / "work"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir()
    timings: dict[str, float] = {}

    @contextmanager
    def stage(name):
        t = time.perf_counter()
        log.info("stage %s ...", name)
        write_json(out_dir / 'progress.json', {'state': 'running', 'stage': name, 'timings': timings})
        try:
            yield
        except Exception as exc:
            write_json(out_dir / 'progress.json', {'state': 'failed', 'stage': name, 'error': str(exc), 'timings': timings})
            raise
        timings[f"{name}_seconds"] = round(time.perf_counter() - t, 3)
        log.info("stage %s done in %.2fs", name, timings[f"{name}_seconds"])

    sampler = RssSampler()
    sampler.start()
    wall = time.perf_counter()
    con = connect(cfg, work / "trace.duckdb", project_path(cfg, cfg["engine"]["temp_directory"]) / out_dir.name)
    report: dict = {"version": __version__}
    @contextmanager
    def blocking_budget():
        previous_threads=int(one(con,"SELECT current_setting('threads')")[0])
        previous_memory=one(con,"SELECT current_setting('memory_limit')")[0]
        run(con,f"SET threads={min(previous_threads,int(cfg['engine'].get('blocking_threads',4)))}")
        if cfg['engine'].get('blocking_memory_limit'):
            run(con,f"SET memory_limit={lit(cfg['engine']['blocking_memory_limit'])}")
        try:
            yield
        finally:
            run(con,f'SET threads={previous_threads}')
            run(con,f'SET memory_limit={lit(previous_memory)}')
    try:
        with stage("ingest"):
            scan_threads=int(one(con,"SELECT current_setting('threads')")[0])
            read_threads=min(scan_threads,int(cfg['ingest'].get('threads',4)))
            if read_threads < 1:
                raise ValueError('ingest.threads must be positive')
            run(con,f'SET threads={read_threads}')
            try:
                report["ingest"] = ingest(con, cfg, input_dir, work)
                report['ingest']['read_threads']=read_threads
            finally:
                run(con,f'SET threads={scan_threads}')
            quality=report['ingest']
            report['input_quality']='partially_quarantined' if any(quality.get(key,0) for key in ('quarantined_rows','adapter_rejected_records','reader_rejected_records')) else 'valid_for_supported_schema'
        if on_ingested is not None:on_ingested(work/'events.parquet')
        rules_dir = project_path(cfg, cfg["detection"]["rules_dir"])
        rules, errors = load_rules(rules_dir)
        for e in errors:
            log.warning("rule rejected: %s", e)
        report["rules"] = {"loaded": len(rules), "rejected": errors, "ruleset_hash": _hash_dir(rules_dir, "*.y*ml")}
        report['rules']['covered_techniques']=sorted({technique for rule in rules.values() for technique in rule.techniques})
        inventory=rules_dir/'community'/'manifest.json'
        if inventory.exists():
            pack=json.loads(inventory.read_text(encoding='utf-8-sig'))
            report['rules']['community']={'commit':pack['commit'],**pack['summary']}
        with stage("detect"):
            report["detect"] = detect(con, cfg, rules)
        mapping_path = project_path(cfg, "configs/attack_mapping.yaml")
        with stage("label"):
            report["label"] = label(con, load_mapping(mapping_path))
        sup_path = project_path(cfg, "configs/suppressions.yaml")
        suppressions = (yaml.safe_load(sup_path.read_text(encoding="utf-8-sig")) or {}).get("suppressions") or [] if sup_path.exists() else []
        with stage("correlate"), blocking_budget():
            report["signals"] = build_signals(con, cfg, suppressions)
            edges = link_edges(con, cfg)
            promoted, isolated = assemble(con, cfg, edges)
            record_assignment(con, promoted, isolated, work)
            report["correlate"] = {"edges": len(edges)}
        with stage("materialize"), blocking_budget():
            graph = AccessGraph(con, cfg)
            report["output"] = materialize(con, cfg, out_dir, promoted, isolated, graph, edges)
    finally:
        finish_query_profile(con)
        con.close()
        peak = sampler.stop()
    timings["total_wall_seconds"] = round(time.perf_counter() - wall, 3)
    report["timings"] = timings
    report["peak_process_tree_rss_bytes"] = peak
    report["peak_process_tree_rss_gb"] = round(peak / 1024 ** 3, 3)
    report["machine"] = {"platform": platform.platform(), "cpus": psutil.cpu_count(),
                         "ram_gb": round(psutil.virtual_memory().total / 1024 ** 3, 1),
                         "memory_limit": cfg["engine"]["memory_limit"],
                         'blocking_memory_limit':cfg['engine'].get('blocking_memory_limit'),
                         'threads':cfg['engine'].get('threads'), 'read_threads':cfg['ingest'].get('threads',4)}
    report["attack_mapping_version"] = report.get("label", {}).get("attack_version")
    write_json(out_dir / 'run_metrics.json', report)
    write_json(out_dir / 'progress.json', {'state': 'complete', 'stage': 'complete', 'timings': timings,'input_quality':report['input_quality']})
    if not keep_work:
        shutil.rmtree(work, ignore_errors=True)
    return report
