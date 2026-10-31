"""PASS 1: stream raw NDJSON (ECS) logs once, normalize, write compact Parquet.

Nothing here pulls raw rows into Python: DuckDB reads the files in parallel, projects only the
columns below, spills to disk under memory pressure and writes zstd Parquet.
"""
from __future__ import annotations

import logging
import hashlib
import json
from pathlib import Path

from tracekc.adapters import convert, input_format
from tracekc.engine import one, run
from tracekc.sigma import lit

log = logging.getLogger(__name__)

# Explicit schema: no inference pass over 50 GB, and unknown keys are ignored.
ECS_COLUMNS = {
    "message": "VARCHAR",
    "@timestamp": "VARCHAR",
    "event": "STRUCT(id VARCHAR, kind VARCHAR, category VARCHAR[], type VARCHAR[], action VARCHAR, "
             "severity INTEGER, module VARCHAR, dataset VARCHAR, outcome VARCHAR)",
    "host": "STRUCT(name VARCHAR, hostname VARCHAR, ip VARCHAR[], os STRUCT(type VARCHAR))",
    "user": "STRUCT(name VARCHAR, domain VARCHAR)",
    "process": "STRUCT(pid BIGINT, name VARCHAR, executable VARCHAR, command_line VARCHAR, entity_id VARCHAR, "
               "parent STRUCT(pid BIGINT, name VARCHAR, entity_id VARCHAR))",
    "source": "STRUCT(ip VARCHAR, port INTEGER)",
    "destination": "STRUCT(ip VARCHAR, port INTEGER, domain VARCHAR)",
    "network": "STRUCT(transport VARCHAR, direction VARCHAR, protocol VARCHAR, bytes BIGINT)",
    "dns": "STRUCT(question STRUCT(name VARCHAR, type VARCHAR), response_code VARCHAR, resolved_ip VARCHAR[])",
    "file": "STRUCT(path VARCHAR, name VARCHAR, size BIGINT, extension VARCHAR)",
    "registry": "STRUCT(path VARCHAR, data STRUCT(strings VARCHAR[]))",
    "winlog": "STRUCT(event_id INTEGER, logon STRUCT(type VARCHAR))",
    "threat": "STRUCT(framework VARCHAR, technique STRUCT(id VARCHAR[], name VARCHAR[]), tactic STRUCT(name VARCHAR[]))",
    "rule": "STRUCT(id VARCHAR, name VARCHAR, severity VARCHAR)",
    "labels": "STRUCT(synthetic VARCHAR, simulated_detection VARCHAR)",
    "labels_extra": "STRUCT(failed_count_5min BIGINT, files_renamed_60s BIGINT)",
}

NORMALIZE_SQL = r"""
SELECT
  coalesce(event.id, md5(concat_ws('|', filename, "@timestamp", host.name, event.action,
           CAST(process.pid AS VARCHAR), source.ip, destination.ip, file.path, registry.path))) AS event_id,
  epoch_ms(try_cast("@timestamp" AS TIMESTAMPTZ)) AS ts_ms,
  lower(event.kind) AS kind,
  lower(event.dataset) AS dataset,
  lower(event.action) AS action,
  lower(event.category[1]) AS category,
  lower(event.outcome) AS outcome,
  event.severity AS vendor_severity,
  nullif(upper(CASE WHEN ipv4_int(coalesce(host.name, host.hostname)) IS NOT NULL
                   THEN coalesce(host.name, host.hostname)
                   ELSE split_part(coalesce(host.name, host.hostname), '.', 1) END), '') AS host,
  host.ip AS host_ips,
  lower(host.os.type) AS os_type,
  nullif(lower(regexp_replace(user.name, '^.*\\|@.*$', '', 'g')), '') AS user_name,
  user.domain AS user_domain,
  source.ip AS src_ip, source.port AS src_port,
  destination.ip AS dst_ip, destination.port AS dst_port, lower(destination.domain) AS dst_domain,
  lower(network.direction) AS direction, lower(network.protocol) AS net_protocol,
  lower(network.transport) AS net_transport, network.bytes AS net_bytes,
  lower(process.name) AS proc_name, process.pid AS proc_pid, process.command_line AS proc_cmd,
  process.executable AS proc_exe, process.entity_id AS proc_entity_id,
  lower(process.parent.name) AS parent_name, process.parent.pid AS parent_pid,
  process.parent.entity_id AS parent_entity_id, message AS message,
  file.path AS file_path, file.name AS file_name, lower(file.extension) AS file_ext, file.size AS file_size,
  registry.path AS reg_path, array_to_string(registry.data.strings, ';') AS reg_data,
  lower(dns.question.name) AS dns_name,
  winlog.event_id AS win_event_id, lower(winlog.logon.type) AS logon_type,
  rule.id AS vendor_rule_id, rule.name AS vendor_rule_name, lower(rule.severity) AS vendor_rule_severity,
  threat.technique.id AS vendor_techniques, threat.tactic.name AS vendor_tactics,
  coalesce(labels.simulated_detection = 'true', FALSE) AS gt_label,
  labels_extra.failed_count_5min AS failed_count, labels_extra.files_renamed_60s AS renamed_count,
  filename AS src_file
FROM raw
"""


def find_inputs(input_dir: Path, patterns: list[str]) -> list[Path]:
    if input_dir.is_file():
        return [input_dir]
    files = {p for pat in patterns for p in input_dir.rglob(pat) if p.is_file()}
    return sorted(files)


def quarantine_utf8(reader, cache, key, maximum, base_offset=0, source_path=None):
    """Stream malformed byte spans to a compact offset/hash ledger; leave source bytes intact."""
    import base64
    import re
    clean=reader.with_suffix('.clean.log');diagnostics=cache/(key+'.quarantine.jsonl')
    prefix=re.compile(rb'(?:<\d+>)?date=\d{4}-\d\d-\d\d time=')
    fields=re.compile(rb'([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|[^ \r\n]+)')
    rejected=0;span=None
    with reader.open('rb') as source,clean.open('wb') as output,diagnostics.open('w',encoding='utf-8') as ledger:
        def flush():
            nonlocal span
            if span:
                span['sha256']=span.pop('_digest').hexdigest()
                ledger.write(json.dumps(span)+'\n');span=None
        while True:
            offset=source.tell();line=source.readline(maximum+1)
            if not line:break
            reason=None
            if len(line)>maximum:reason='record_exceeds_maximum_object_size'
            elif not prefix.match(line) or b' devname=' not in line:reason='unrecognized_fortigate_record'
            else:
                try:
                    line.decode('utf-8')
                    keys=[item[0] for item in fields.findall(line)]
                    if len(keys)!=len(set(keys)):reason='duplicate_key'
                except UnicodeError:reason='invalid_utf8'
            if reason:
                rejected+=1
                if span is None:
                    span={'source_file':str(source_path or reader),'source_byte_offset':base_offset+offset,
                          'bytes':0,'rejected_physical_lines':0,'preview_base64':base64.b64encode(line[:128]).decode(),
                          'reason':reason,'_digest':hashlib.sha256()}
                while True:
                    span['_digest'].update(line);span['bytes']+=len(line)
                    if line.endswith(b'\n') or not line:break
                    line=source.readline(maximum+1)
                span['rejected_physical_lines']+=1
            else:
                flush();output.write(line)
        flush()
    clean.replace(reader)
    return rejected,[diagnostics.name]


def ingest_chunks(con, source, fmt, settings, cache, work, reader_signature):
    from tracekc.read_cache import prepare, commit
    before=source.stat()
    immutable_signature=reader_signature+f':{before.st_size}:{before.st_mtime_ns}'
    parsed=0
    while True:
        plan=prepare(source,cache,work,immutable_signature,int(settings['maximum_object_size']),
                     chunk_bytes=int(settings['chunk_bytes']),allow_final=True)
        if plan['reader'] is None:
            return plan['prior'],parsed,plan['prior_rejected']
        shard=cache/(plan['key']+'.parquet');temporary=shard.with_suffix('.tmp.parquet')
        reader=plan['reader']
        if fmt=='fortigate':
            from tracekc.fortigate import raw_view
            raw_view(con,reader,ECS_COLUMNS,int(settings['maximum_object_size']),identity_source=source)
        else:
            columns='{' + ', '.join(f'{lit(k)}: {lit(v)}' for k,v in ECS_COLUMNS.items()) + '}'
            run(con,f"CREATE OR REPLACE VIEW raw AS SELECT * FROM read_json({lit(reader)},format='newline_delimited',columns={columns},filename=true,ignore_errors={str(bool(settings.get('ignore_errors',False))).lower()},maximum_object_size={int(settings['maximum_object_size'])})")
        normalize=NORMALIZE_SQL.replace('filename AS src_file',f'{lit(source)} AS src_file').replace('filename, "@timestamp"',f'{lit(source)}, "@timestamp"')
        statement=f'COPY ({normalize}) TO {lit(temporary)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880)'
        try:
            run(con,statement)
        except Exception as exc:
            if fmt!='fortigate' or not settings.get('quarantine_invalid_utf8',True) or not any(marker in str(exc) for marker in ('Invalid unicode','Map keys must be unique','CSV Error')):
                raise
            count,files=quarantine_utf8(reader,cache,plan['key'],int(settings['maximum_object_size']),plan['offset']-plan['bytes'],source)
            plan['new_rejected']=count;plan['rejection_files'].extend(files)
            log.warning('Quarantined %s malformed physical-line fragments in %s; source offsets/hashes recorded and original file unchanged',count,source.name)
            if reader.stat().st_size==0:
                columns=', '.join(f'NULL::{dtype} AS \"{name}\"' for name,dtype in ECS_COLUMNS.items())
                run(con,"CREATE OR REPLACE VIEW raw AS SELECT "+columns+", NULL::VARCHAR AS filename WHERE FALSE")
            run(con,statement)
        after=source.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            temporary.unlink(missing_ok=True)
            raise ValueError('Closed input changed during chunked ingestion; retry when the writer finishes')
        temporary.replace(shard);group=plan['prior']+[shard];commit(plan,group);reader.unlink()
        parsed+=plan['bytes']
        log.info('checkpoint %s: %s/%s bytes (%s chunks)',source.name,plan['offset'],before.st_size,len(group))
        progress=work.parent/'progress.json';temporary_progress=progress.with_suffix('.tmp')
        temporary_progress.write_text(json.dumps({'state':'running','stage':'ingest','source':source.name,
              'completed_bytes':plan['offset'],'source_bytes':before.st_size,'chunks':len(group)}),encoding='utf-8')
        temporary_progress.replace(progress)
        if plan['offset']==before.st_size:return group,parsed,plan.get('prior_rejected',0)+plan.get('new_rejected',0)


def ingest(con, cfg: dict, input_dir: Path, work_dir: Path) -> dict:
    files = find_inputs(input_dir, cfg["ingest"]["patterns"])
    if not files:
        raise FileNotFoundError(f"no supported input files under {input_dir}")
    settings = cfg['ingest']
    columns = "{" + ", ".join(f"{lit(k)}: {lit(v)}" for k, v in ECS_COLUMNS.items()) + "}"
    incremental = settings.get('incremental', False)
    cache = work_dir.parent / 'ingest_cache' if incremental else work_dir / 'shards'
    cache.mkdir(parents=True, exist_ok=True)
    shards, manifest, formats = [], [], {}
    reused = rejected = parsed_bytes = deferred_bytes = reader_rejected = 0
    reader_signature = hashlib.sha256((NORMALIZE_SQL + json.dumps(ECS_COLUMNS, sort_keys=True) + json.dumps(settings,sort_keys=True)).encode()
        + Path(__file__).with_name('adapters.py').read_bytes() + Path(__file__).with_name('fortigate.py').read_bytes()).hexdigest()
    for number, source in enumerate(files, 1):
        before = source.stat()
        fmt = input_format(source, settings.get('format', 'auto'))
        chunk_bytes=int(settings.get('chunk_bytes',0))
        if incremental and not settings.get('append_only') and chunk_bytes and before.st_size>chunk_bytes and fmt in {'ecs','fortigate'} and source.suffix!='.gz':
            group,processed,invalid=ingest_chunks(con,source,fmt,settings,cache,work_dir,reader_signature)
            reader_rejected+=invalid
            shards.extend(group);parsed_bytes+=processed;reused+=int(processed==0)
            formats[fmt]=formats.get(fmt,0)+1
            manifest.append({'source':str(source),'size':before.st_size,'format':fmt,'shards':len(group),'rejected_records':0})
            continue
        append = None
        if incremental and settings.get('append_only', False) and fmt in {'ecs','fortigate'} and source.suffix != '.gz':
            from tracekc.read_cache import prepare
            append = prepare(source, cache, work_dir, reader_signature, int(settings['maximum_object_size']))
            deferred_bytes += append['deferred_tail_bytes']
            if append['reader'] is None:
                shards.extend(append['prior']); reused += 1
                formats[fmt] = formats.get(fmt,0)+1
                manifest.append({'source':str(source),'size':before.st_size,'format':fmt,'append_offset':append['offset'],'rejected_records':0})
                continue
        signature = json.dumps([str(source.resolve()), before.st_size, before.st_mtime_ns, reader_signature], sort_keys=True)
        key = append['key'] if append else hashlib.sha256(signature.encode()).hexdigest()
        shard = cache / (key + '.parquet')
        metadata = cache / (key + '.json')
        cached = shard.exists() and metadata.exists()
        if cached:
            info = json.loads(metadata.read_text(encoding='utf-8'))
            reused += 1
        else:
            fmt = input_format(source, settings.get('format', 'auto'))
            info = {'format': fmt, 'rejected_records': 0}
            reader = append['reader'] if append else source
            if fmt not in {'ecs', 'fortigate'}:
                reader = work_dir / f'adapted-{key}.ndjson'
                info.update(convert(source, reader, fmt, int(settings['maximum_object_size'])))
                reject_path = reader.with_suffix('.rejects.ndjson')
                (cache / (key + '.rejects.ndjson')).write_bytes(reject_path.read_bytes())
            if fmt == 'fortigate':
                from tracekc.fortigate import raw_view
                raw_view(con, reader, ECS_COLUMNS, int(settings['maximum_object_size']), identity_source=source)
            else:
                run(con, f"""CREATE OR REPLACE VIEW raw AS SELECT * FROM read_json({lit(reader)},
                    format='newline_delimited', columns={columns}, filename=true,
                    ignore_errors={str(bool(settings.get('ignore_errors', False))).lower()}, compression='auto',
                    maximum_object_size={int(settings['maximum_object_size'])})""")
            temporary = shard.with_suffix('.tmp.parquet')
            normalize = NORMALIZE_SQL.replace('filename AS src_file', f'{lit(source)} AS src_file')
            normalize = normalize.replace('filename, "@timestamp"', f'{lit(source)}, "@timestamp"')
            run(con, f"COPY ({normalize}) TO {lit(temporary)} (FORMAT parquet, COMPRESSION zstd)")
            after = source.stat()
            if not append and (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                temporary.unlink(missing_ok=True)
                raise ValueError(f'{source.name}: input changed during ingestion; retry after the writer finishes')
            temporary.replace(shard)
            metadata.write_text(json.dumps(info), encoding='utf-8')
            parsed_bytes += append['bytes'] if append else before.st_size
            if reader != source:
                reader.unlink(missing_ok=True)
        rejected += info['rejected_records']
        formats[info['format']] = formats.get(info['format'], 0) + 1
        if append:
            from tracekc.read_cache import commit
            group = append['prior'] + [shard]
            commit(append, group)
            shards.extend(group)
        else:
            shards.append(shard)
        manifest.append({'source': str(source), 'size': before.st_size, 'cache_key': key, **info})
        log.info('read %s/%s files: %s%s', number, len(files), source.name, ' (cached)' if cached else '')
    shard_list = '[' + ', '.join(lit(p) for p in shards) + ']'
    run(con, f'CREATE OR REPLACE VIEW normalized AS SELECT * FROM read_parquet({shard_list})')
    events_path = work_dir / 'events.parquet'
    dedupe = 'QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY ts_ms) = 1' if settings.get('dedupe_events', True) else ''
    run(con, f"COPY (SELECT * FROM normalized {dedupe}) TO {lit(events_path)} (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880)")
    run(con, f'CREATE OR REPLACE VIEW events_all AS SELECT * FROM read_parquet({lit(events_path)})')
    run(con, 'CREATE OR REPLACE VIEW events AS SELECT * FROM events_all WHERE ts_ms IS NOT NULL AND host IS NOT NULL')
    run(con, 'CREATE OR REPLACE VIEW bad_rows AS SELECT * FROM events_all WHERE ts_ms IS NULL OR host IS NULL')
    # Conservative resolution: do not assign an IP that has several observed owners.
    run(con, """CREATE OR REPLACE TABLE ip_host AS
        SELECT ip, min(host) AS host, min(ts_ms) AS first_seen_ms FROM
        (SELECT unnest(host_ips) AS ip, host, ts_ms FROM events WHERE host_ips IS NOT NULL)
        WHERE ip IS NOT NULL GROUP BY ip HAVING count(DISTINCT host) = 1""")
    run(con, """CREATE OR REPLACE VIEW ev AS
        WITH launches AS (SELECT host, proc_pid, ts_ms, coalesce(proc_entity_id, event_id) AS identity
                          FROM events WHERE action = 'process_created' AND proc_pid IS NOT NULL
                          QUALIFY row_number() OVER (PARTITION BY host, proc_pid, ts_ms ORDER BY event_id) = 1),
        resolved AS (SELECT e.* EXCLUDE (proc_entity_id), coalesce(e.proc_entity_id, p.identity) AS proc_entity_id
                     FROM events e ASOF LEFT JOIN launches p
                     ON e.host = p.host AND e.proc_pid = p.proc_pid AND e.ts_ms >= p.ts_ms)
        SELECT e.*, sh.host AS src_host, dh.host AS dst_host FROM resolved e
        LEFT JOIN ip_host sh ON e.src_ip = sh.ip AND sh.first_seen_ms <= e.ts_ms
        LEFT JOIN ip_host dh ON e.dst_ip = dh.ip AND dh.first_seen_ms <= e.ts_ms""")
    total, bad, tmin, tmax = one(con, 'SELECT count(*), count(*) FILTER (WHERE ts_ms IS NULL OR host IS NULL), min(ts_ms), max(ts_ms) FROM events_all')
    run(con, f"COPY (SELECT *, CASE WHEN ts_ms IS NULL AND host IS NULL THEN 'missing_time_and_host' WHEN ts_ms IS NULL THEN 'missing_time' ELSE 'missing_host' END AS quarantine_reason FROM bad_rows) TO {lit(work_dir.parent / 'quarantine.parquet')} (FORMAT parquet)")
    (work_dir.parent / 'ingest_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    raw_count = one(con, 'SELECT count(*) FROM normalized')[0]
    stats = {'input_files': len(files), 'input_bytes': sum(f.stat().st_size for f in files),
             'events': int(total), 'records_before_deduplication':raw_count, 'quarantined_rows': int(bad), 'parsed_input_bytes': parsed_bytes, 'deferred_tail_bytes': deferred_bytes, 'normalized_shards': len(shards), 'duplicates_removed': raw_count - total,
             'adapter_rejected_records': rejected, 'reader_rejected_records':reader_rejected, 'reused_files': reused, 'formats': formats,
             'missing_timestamp': one(con, 'SELECT count(*) FROM events_all WHERE ts_ms IS NULL')[0],
             'missing_host': one(con, 'SELECT count(*) FROM events_all WHERE host IS NULL')[0],
             'missing_user': one(con, 'SELECT count(*) FROM events WHERE user_name IS NULL')[0],
             'ts_min_ms': tmin, 'ts_max_ms': tmax,
             'hosts_with_ips': one(con, 'SELECT count(DISTINCT host) FROM ip_host')[0],
             'parquet_bytes': events_path.stat().st_size}
    if total == bad:
        raise ValueError('no valid events with both a timestamp and host; inspect quarantine.parquet')
    log.info('ingested %s events from %s files (%s quarantined)', total, len(files), bad)
    return stats
