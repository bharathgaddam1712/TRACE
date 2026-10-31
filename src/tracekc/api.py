"""FastAPI over the precomputed JSON (FR-7). Every request is served from memory: no query runs
when an incident is opened. Files are reloaded when index.json changes (live mode, B-5)."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from tracekc.config import PROJECT_ROOT


class Store:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.lock = threading.Lock()
        self.mtime = None
        self.index: list[dict] = []
        self.incidents: dict[int, dict] = {}
        self.findings: dict = {}
        self.metrics: dict = {}
        self.refresh()

    def _read(self, name: str, default):
        p = self.out_dir / name
        return json.loads(p.read_text()) if p.exists() else default

    def refresh(self) -> None:
        idx = self.out_dir / "index.json"
        mtime = idx.stat().st_mtime if idx.exists() else None
        if mtime == self.mtime:
            return
        with self.lock:
            index = self._read("index.json", [])
            incidents = {}
            for f in (self.out_dir / "incidents").glob("*.json"):
                inc = json.loads(f.read_text())
                incidents[int(inc["id"])] = inc
            self.index, self.incidents = index, incidents
            self.findings = self._read("findings.json", {})
            self.metrics = self._read("run_metrics.json", {})
            self.mtime = mtime


def create_app(out_dir: Path) -> FastAPI:
    store = Store(out_dir)
    app = FastAPI(title="TRACE - kill chain and attack path analysis", version="0.1.0")

    def get(inc_id: int) -> dict:
        store.refresh()
        inc = store.incidents.get(inc_id)
        if inc is None:
            raise HTTPException(status_code=404, detail=f"incident {inc_id} not found")
        return inc

    @app.get("/health")
    def health():
        store.refresh()
        return {"status": "ok", "incidents": len(store.index), "out_dir": str(out_dir)}

    @app.get("/incidents")
    def incidents(min_score: float = 0, limit: int = 100):
        store.refresh()
        return [i for i in store.index if i["score"] >= min_score][:limit]

    @app.get("/incidents/{inc_id}")
    def incident(inc_id: int):
        return get(inc_id)

    @app.get("/incidents/{inc_id}/path")
    def path(inc_id: int):
        inc = get(inc_id)
        return {"id": inc["id"], "title": inc["title"], "score": inc["score"], "host_path": inc["host_path"],
                "host_path_text": inc["host_path_text"], "tactics": inc["tactics"],
                "timeline": [{k: s.get(k) for k in ("step", "ts", "technique", "technique_name", "tactic",
                                                     "kill_chain_stage", "host", "user", "src_host", "dst_ip",
                                                     "title", "merged_detections", "link")} for s in inc["timeline"]],
                "graph": inc["graph"], "lookahead": inc["lookahead"]}

    @app.get("/incidents/{inc_id}/report", response_class=PlainTextResponse)
    def report(inc_id: int):
        return get(inc_id)["narrative"]

    @app.get("/findings")
    def findings(limit: int = 200):
        store.refresh()
        f = dict(store.findings)
        f["findings"] = f.get("findings", [])[:limit]
        return f

    @app.get("/metrics")
    def metrics():
        store.refresh()
        return store.metrics

    web = PROJECT_ROOT / "web"
    if web.exists():
        app.mount("/", StaticFiles(directory=web, html=True), name="web")
    return app
