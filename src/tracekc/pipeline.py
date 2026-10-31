"""Stage orchestration with per-stage timings and peak process-tree RSS (benchmark protocol)."""
from __future__ import annotations

import hashlib
import json
import logging
import platform
import shutil
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import psutil
import yaml

from tracekc import __version__
from tracekc.config import project_path
from tracekc.correlate import assemble, build_signals, link_edges, record_assignment
from tracekc.detect import detect
from tracekc.engine import connect
from tracekc.ingest import ingest
from tracekc.label import label, load_mapping
from tracekc.materialize import materialize
from tracekc.reach import AccessGraph
from tracekc.sigma import load_rules

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


def run_pipeline(cfg: dict, input_dir: Path, out_dir: Path, keep_work: bool = False) -> dict:
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
        yield
        timings[f"{name}_seconds"] = round(time.perf_counter() - t, 3)
        log.info("stage %s done in %.2fs", name, timings[f"{name}_seconds"])

    sampler = RssSampler()
    sampler.start()
    wall = time.perf_counter()
    con = connect(cfg, work / "trace.duckdb", project_path(cfg, cfg["engine"]["temp_directory"]) / out_dir.name)
    report: dict = {"version": __version__}
    try:
        with stage("ingest"):
            report["ingest"] = ingest(con, cfg, input_dir, work)
        rules_dir = project_path(cfg, cfg["detection"]["rules_dir"])
        rules, errors = load_rules(rules_dir)
        for e in errors:
            log.warning("rule rejected: %s", e)
        report["rules"] = {"loaded": len(rules), "rejected": errors, "ruleset_hash": _hash_dir(rules_dir, "*.y*ml")}
        with stage("detect"):
            report["detect"] = detect(con, cfg, rules)
        mapping_path = project_path(cfg, "configs/attack_mapping.yaml")
        with stage("label"):
            report["label"] = label(con, load_mapping(mapping_path))
        sup_path = project_path(cfg, "configs/suppressions.yaml")
        suppressions = (yaml.safe_load(sup_path.read_text()) or {}).get("suppressions") or [] if sup_path.exists() else []
        with stage("correlate"):
            report["signals"] = build_signals(con, cfg, suppressions)
            edges = link_edges(con, cfg)
            promoted, isolated = assemble(con, cfg, edges)
            record_assignment(con, promoted, isolated, work)
            report["correlate"] = {"edges": len(edges)}
        with stage("materialize"):
            graph = AccessGraph(con, cfg)
            report["output"] = materialize(con, cfg, out_dir, promoted, isolated, graph)
    finally:
        con.close()
        peak = sampler.stop()
    timings["total_wall_seconds"] = round(time.perf_counter() - wall, 3)
    report["timings"] = timings
    report["peak_process_tree_rss_bytes"] = peak
    report["peak_process_tree_rss_gb"] = round(peak / 1024 ** 3, 3)
    report["machine"] = {"platform": platform.platform(), "cpus": psutil.cpu_count(),
                         "ram_gb": round(psutil.virtual_memory().total / 1024 ** 3, 1),
                         "memory_limit": cfg["engine"]["memory_limit"]}
    report["attack_mapping_version"] = report.get("label", {}).get("attack_version")
    (out_dir / "run_metrics.json").write_text(json.dumps(report, indent=1, default=str))
    if not keep_work:
        shutil.rmtree(work, ignore_errors=True)
    return report
