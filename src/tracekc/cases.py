"""Local analyst state and append-only audit events, keyed by stable incident fingerprint."""
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
import json
import sqlite3

from pydantic import BaseModel, Field, ConfigDict


class CaseUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    status: Literal['new', 'investigating', 'contained', 'closed']
    note: str = Field(default='', max_length=10000)
    version: int = Field(ge=0)


class Cases:
    def __init__(self, root: Path):
        self.path = root / 'analyst.sqlite3'
        root.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as con:
            con.executescript('''CREATE TABLE IF NOT EXISTS cases (fingerprint TEXT PRIMARY KEY, status TEXT NOT NULL, version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS case_history (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, ts TEXT NOT NULL, status TEXT NOT NULL, note TEXT NOT NULL);''')

    def get(self, fingerprint):
        with sqlite3.connect(self.path) as con:
            row = con.execute('SELECT status, version FROM cases WHERE fingerprint=?', (fingerprint,)).fetchone() or ('new', 0)
            history = con.execute('SELECT ts, status, note FROM case_history WHERE fingerprint=? ORDER BY id', (fingerprint,)).fetchall()
        return {'status': row[0], 'version': row[1], 'history': [{'ts': ts, 'status': status, 'note': note} for ts, status, note in history]}

    def statuses(self):
        with sqlite3.connect(self.path) as con:
            return dict(con.execute('SELECT fingerprint, status FROM cases').fetchall())

    def update(self, fingerprint, update: CaseUpdate):
        with sqlite3.connect(self.path) as con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT version FROM cases WHERE fingerprint=?', (fingerprint,)).fetchone() or (0,)
            if row[0] != update.version:
                raise ValueError('Case changed since it was opened; reload and try again')
            con.execute('INSERT OR REPLACE INTO cases VALUES (?, ?, ?)', (fingerprint, update.status, update.version + 1))
            con.execute('INSERT INTO case_history (fingerprint, ts, status, note) VALUES (?, ?, ?, ?)',
                        (fingerprint, datetime.now(timezone.utc).isoformat(), update.status, update.note))
        return self.get(fingerprint)
