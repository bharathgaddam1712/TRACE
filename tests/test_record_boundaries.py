"""Closed-file framing must let quarantine inspect oversized physical records."""
import hashlib
import json
import shutil

import pytest

from tracekc.read_cache import chunk_end


def test_strict_boundary_unchanged_and_opt_in_preserves_physical_record(tmp_path):
    source=tmp_path/'events.log'
    data=b'ok\n'+b'\0'*100+b'date=not-a-new-record\n'+b'next\n'
    source.write_bytes(data)
    with pytest.raises(ValueError,match='unterminated record'):
        chunk_end(source,0,len(data),16,40,True)
    # Opt-in alone cannot change append-only framing.
    with pytest.raises(ValueError,match='unterminated record'):
        chunk_end(source,0,len(data),16,40,False,True)
    end=chunk_end(source,0,len(data),16,40,True,True)
    assert data[:end].endswith(b'date=not-a-new-record\n')
    assert data[end:]==b'next\n'
    assert chunk_end(source,end,len(data),16,40,True,True)==len(data)


def test_boundary_scan_is_block_bounded_and_handles_final_unterminated_record(tmp_path):
    source=tmp_path/'large.log';source.write_bytes(b'\0'*(2*1024*1024+13))
    assert chunk_end(source,0,source.stat().st_size,16,40,True,True)==source.stat().st_size


def test_prefetch_defers_oversized_range_to_foreground(tmp_path,monkeypatch):
    from tracekc import native_reader
    source=tmp_path/'long.log';source.write_bytes(b'\0'*100+b'\n')
    def unexpected(*args,**kwargs):raise AssertionError('Do not tokenize an oversized speculative range')
    monkeypatch.setattr(native_reader,'tokenize',unexpected)
    with native_reader.TokenPrefetch(True) as reader:
        reader.ahead(source,tmp_path,16,0,101,40,'json',allow_oversized=True)
        assert reader.pending is None


@pytest.mark.parametrize('native',[False,True])
@pytest.mark.parametrize('terminated',[False,True])
def test_oversized_quarantine_keeps_neighbors_hashes_offsets_and_replay(tmp_path,native,terminated):
    if native and not (shutil.which('gcc') or shutil.which('clang')):
        pytest.skip('optional C compiler unavailable')
    from tracekc.config import load_config
    from tracekc.engine import connect
    from tracekc.ingest import ingest
    prefix=b'date=2026-10-31 time=01:02:03 tz="+0000" devname="FW" type=traffic subtype=forward '
    # Fill at least one ordinary chunk first, so ledger offsets are nonzero.
    first=(prefix+b'srcip=10.0.0.1 dstip=8.8.8.8 action=accept\n')*20
    last=prefix+b'srcip=10.0.0.2 dstip=1.1.1.1 action=deny\n'
    # A prefix-looking continuation must not become a separate accepted event.
    bad=b'\0'*10000+prefix+b'not-a-separate-record'+(b'\n' if terminated else b'')
    if not terminated:last=b''
    source=tmp_path/'events.log';original=first+bad+last;source.write_bytes(original)
    cfg=load_config(overrides=['engine.threads=1','engine.memory_limit=256MB',
        'ingest.format=fortigate','ingest.maximum_object_size=1024','ingest.chunk_bytes=2048'])
    cfg['ingest']['native_fortigate']=native
    work=tmp_path/'out/work';work.mkdir(parents=True)
    con=connect(cfg,work/'test.duckdb',work/'spill')
    try:
        stats=ingest(con,cfg,source,work)
        assert stats['valid_events']==(2 if terminated else 1)
        assert stats['reader_rejected_records']==1 and stats['reader_rejected_bytes']==len(bad)
        rows=con.execute('SELECT event_id FROM ev ORDER BY event_id').fetchall()
        replay=ingest(con,cfg,source,work)
        assert replay['parsed_input_bytes']==0 and replay['reader_rejected_bytes']==len(bad)
        assert con.execute('SELECT event_id FROM ev ORDER BY event_id').fetchall()==rows
        ledger=[json.loads(line) for p in (tmp_path/'out/ingest_cache').glob('*.quarantine.jsonl')
                for line in p.read_text().splitlines()]
        assert len(ledger)==1
        assert ledger[0]['source_byte_offset']==len(first)
        assert ledger[0]['bytes']==len(bad) and ledger[0]['sha256']==hashlib.sha256(bad).hexdigest()
        assert ledger[0]['reason']=='record_exceeds_maximum_object_size'
        assert source.read_bytes()==original
    finally:con.close()


def test_all_rejected_extended_range_writes_empty_shard(tmp_path):
    from tracekc.config import load_config
    from tracekc.engine import connect
    from tracekc.ingest import ingest
    source=tmp_path/'zeros.log';source.write_bytes(b'\0'*10000)
    cfg=load_config(overrides=['engine.threads=1','engine.memory_limit=256MB','ingest.format=fortigate',
        'ingest.maximum_object_size=1024','ingest.chunk_bytes=2048','ingest.native_fortigate=false'])
    work=tmp_path/'out/work';work.mkdir(parents=True)
    con=connect(cfg,work/'test.duckdb',work/'spill')
    try:
        # Existing policy still fails a wholly invalid input, after accounting
        # for its bytes rather than crashing in boundary detection.
        with pytest.raises(ValueError,match='no valid events'):
            ingest(con,cfg,source,work)
        cache=tmp_path/'out/ingest_cache'
        checkpoint=json.loads(next(cache.glob('*.checkpoint.json')).read_text())
        assert checkpoint['offset']==10000 and checkpoint['rejected_records']==1
        ledger=json.loads(next(cache.glob('*.quarantine.jsonl')).read_text())
        assert ledger['bytes']==10000 and ledger['sha256']==hashlib.sha256(source.read_bytes()).hexdigest()
        assert con.execute('SELECT count(*) FROM normalized').fetchone()[0]==0
    finally:con.close()
