"""PASS 1: stream raw NDJSON (ECS) logs once, normalize, write compact Parquet.

Nothing here pulls raw rows into Python: DuckDB reads the files in parallel, projects only the
columns below, spills to disk under memory pressure and writes zstd Parquet.
"""
from __future__ import annotations

import logging
import hashlib
import json
import time
from contextlib import contextmanager
from pathlib import Path

from tracekc.adapters import convert, input_format
from tracekc.engine import one, run
from tracekc.sigma import lit

log = logging.getLogger(__name__)


@contextmanager
def read_timing(timings, name):
    started = time.perf_counter()
    try:
        yield
    finally:
        timings[name] = timings.get(name, 0.0) + time.perf_counter() - started

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
    # Windows Security / Directory Service fields used by the Active Directory rules (Winlogbeat ECS layout).
    "winlog": "STRUCT(event_id INTEGER, record_id VARCHAR, logon STRUCT(type VARCHAR), event_data STRUCT("
              "ServiceName VARCHAR, TicketEncryptionType VARCHAR, TicketOptions VARCHAR, Status VARCHAR, "
              "PreAuthType VARCHAR, Properties VARCHAR, AccessMask VARCHAR, ObjectDN VARCHAR, ObjectName VARCHAR, "
              "ObjectClass VARCHAR, AttributeLDAPDisplayName VARCHAR, AttributeValue VARCHAR, OperationType VARCHAR, "
              "SubjectUserName VARCHAR, TargetUserName VARCHAR, MemberName VARCHAR, ServicePrincipalNames VARCHAR, "
              "IpAddress VARCHAR))",
    "group": "STRUCT(name VARCHAR)",
    "threat": "STRUCT(framework VARCHAR, technique STRUCT(id VARCHAR[], name VARCHAR[]), tactic STRUCT(name VARCHAR[]))",
    "rule": "STRUCT(id VARCHAR, name VARCHAR, severity VARCHAR)",
    "labels": "STRUCT(synthetic VARCHAR, simulated_detection VARCHAR)",
    "labels_extra": "STRUCT(failed_count_5min BIGINT, files_renamed_60s BIGINT)",
}

NORMALIZE_SQL = r"""
SELECT
  -- winlog.record_id keeps same-millisecond Windows events (e.g. 4769 bursts) distinct.
  coalesce(event.id, md5(concat_ws('|', filename, "@timestamp", host.name, event.action,
           CAST(process.pid AS VARCHAR), source.ip, destination.ip, file.path, registry.path,
           winlog.record_id))) AS event_id,
  epoch_ms(try_cast("@timestamp" AS TIMESTAMPTZ)) AS ts_ms,
  lower(event.kind) AS kind,
  lower(event.dataset) AS dataset,
  lower(event.action) AS action,
  lower(event.category[1]) AS category,
  lower(event.outcome) AS outcome,
  event.severity AS vendor_severity,
  nullif(upper(CASE WHEN regexp_full_match(coalesce(host.name, host.hostname), '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                   THEN coalesce(host.name, host.hostname)
                   ELSE split_part(coalesce(host.name, host.hostname), '.', 1) END), '') AS host,
  host.ip AS host_ips,
  lower(host.os.type) AS os_type,
  -- Windows events without ECS user.name: authentication events name the account in
  -- TargetUserName, directory/group changes name the actor in SubjectUserName.
  nullif(lower(regexp_replace(coalesce(user.name,
    CASE WHEN winlog.event_id IN (4624, 4625, 4768, 4769, 4770, 4771, 4776) THEN winlog.event_data.TargetUserName
         ELSE winlog.event_data.SubjectUserName END), '^.*\\|@.*$', '', 'g')), '') AS user_name,
  user.domain AS user_domain,
  -- Windows reports IPv4 clients as ::ffff:a.b.c.d and local or absent clients as '-' / ::1.
  nullif(nullif(regexp_replace(coalesce(source.ip, winlog.event_data.IpAddress), '^::ffff:', ''), '-'), '::1') AS src_ip,
  source.port AS src_port,
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
  lower(winlog.event_data.ServiceName) AS win_service, lower(winlog.event_data.TicketEncryptionType) AS win_ticket_enc,
  lower(winlog.event_data.TicketOptions) AS win_ticket_options, lower(winlog.event_data.Status) AS win_status,
  winlog.event_data.PreAuthType AS win_preauth, lower(winlog.event_data.Properties) AS win_properties,
  lower(winlog.event_data.AccessMask) AS win_access_mask,
  coalesce(winlog.event_data.ObjectDN, winlog.event_data.ObjectName) AS win_object_dn,
  lower(winlog.event_data.ObjectClass) AS win_object_class, winlog.event_data.AttributeLDAPDisplayName AS win_attribute,
  winlog.event_data.AttributeValue AS win_attr_value, winlog.event_data.OperationType AS win_operation,
  lower(winlog.event_data.SubjectUserName) AS win_subject_user, lower(winlog.event_data.TargetUserName) AS win_target_user,
  winlog.event_data.MemberName AS win_member, winlog.event_data.ServicePrincipalNames AS win_spns,
  -- Group-change events (4727-4764) name the group in TargetUserName; ECS moves it to group.name.
  lower(coalesce("group".name, CASE WHEN winlog.event_id BETWEEN 4727 AND 4764
                                    THEN winlog.event_data.TargetUserName END)) AS win_group,
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


def quarantine_utf8(reader, cache, key, maximum, base_offset=0, source_path=None, *, source_range=None):
    """Stream rejected spans to a ledger; optionally clean a source range directly.

    Range mode avoids copying a potentially huge rejected physical record to
    temporary disk before inspecting it. Only accepted records are written.
    """
    import base64
    import re
    clean=reader.with_suffix('.clean.log');diagnostics=cache/(key+'.quarantine.jsonl')
    prefix=re.compile(rb'(?:<\d+>)?date=\d{4}-\d\d-\d\d time=')
    fields=re.compile(rb'([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|[^ \r\n]+)')
    rejected=0;span=None
    origin=source_path if source_range is not None else reader
    start,length=source_range if source_range is not None else (0,reader.stat().st_size)
    with origin.open('rb') as source,clean.open('wb') as output,diagnostics.open('w',encoding='utf-8') as ledger:
        source.seek(start);remaining=length;next_progress=256*1024*1024
        def fragment():
            nonlocal remaining,next_progress
            if not remaining:return b''
            line=source.readline(min(maximum+1,remaining))
            if not line:raise ValueError('Source was truncated during quarantine')
            remaining-=len(line)
            consumed=length-remaining
            if source_range is not None and consumed>=next_progress:
                log.info('Quarantine scan %s: %s/%s source-range bytes',origin.name,consumed,length)
                next_progress=consumed+256*1024*1024
            return line
        def flush():
            nonlocal span
            if span:
                span['sha256']=span.pop('_digest').hexdigest()
                ledger.write(json.dumps(span)+'\n');span=None
        while True:
            offset=source.tell()-start;line=fragment()
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
                    line=fragment()
                span['rejected_physical_lines']+=1
            else:
                flush();output.write(line)
        flush()
    clean.replace(reader)
    return rejected,[diagnostics.name]


def parquet_codec(settings):
    codec=str(settings.get('parquet_compression','zstd')).lower()
    if codec not in {'zstd','snappy','lz4_raw','uncompressed'}:
        raise ValueError('ingest.parquet_compression must be zstd, snappy, lz4_raw or uncompressed')
    return codec


def ingest_chunks(con, source, fmt, settings, cache, work, reader_signature, timings):
    from tracekc.native_reader import TokenPrefetch
    enabled=(fmt=='fortigate' and settings.get('native_fortigate',True)
             and settings.get('native_prefetch',True) and not settings.get('native_in_memory',False))
    with TokenPrefetch(enabled) as prefetch:
        return _ingest_chunks(con,source,fmt,settings,cache,work,reader_signature,timings,prefetch)


def _ingest_chunks(con, source, fmt, settings, cache, work, reader_signature, timings, prefetch):
    from tracekc.read_cache import prepare, commit, materialize
    from tracekc.native_reader import executable, TokenBuffer
    direct_native=(fmt=='fortigate' and settings.get('native_fortigate',True)
                   and executable(str(cache/'native')) is not None)
    memory_handoff=bool(settings.get('native_in_memory',False))
    native_format=settings.get('native_format','csv')
    codec=parquet_codec(settings)
    before=source.stat()
    quarantine_oversized=fmt=='fortigate' and settings.get('quarantine_invalid_utf8',True)
    immutable_signature=reader_signature+f':{before.st_size}:{before.st_mtime_ns}'
    parsed=0
    while True:
        with read_timing(timings, 'segment_copy_and_checkpoint_seconds'):
            plan=prepare(source,cache,work,immutable_signature,int(settings['maximum_object_size']),
                         chunk_bytes=int(settings['chunk_bytes']),allow_final=True,
                         copy_segment=not (direct_native or quarantine_oversized),
                         allow_oversized=quarantine_oversized)
        if plan['reader'] is None:
            return plan['prior'],parsed,plan['prior_rejected'],plan['rejection_files']
        shard=cache/(plan['key']+'.parquet');temporary=shard.with_suffix('.tmp.parquet')
        reader=plan['reader']
        token_reader = None
        quarantined = False
        def prepare_raw():
            nonlocal token_reader
            if quarantined and reader.stat().st_size==0:
                columns=', '.join(f'NULL::{dtype} AS \"{name}\"' for name,dtype in ECS_COLUMNS.items())
                run(con,"CREATE OR REPLACE VIEW raw AS SELECT "+columns+", NULL::VARCHAR AS filename WHERE FALSE")
                return
            if fmt=='fortigate':
                from tracekc.fortigate import raw_view
                if settings.get('native_fortigate', True):
                    from tracekc.native_reader import tokenize
                    with read_timing(timings, 'native_tokenize_seconds'):
                        if direct_native and not quarantined:
                            token_reader=prefetch.get(source,cache,int(settings['maximum_object_size']),in_memory=memory_handoff,
                                                  offset=plan['offset']-plan['bytes'],length=plan['bytes'],destination=reader.with_suffix('.tokens.'+native_format),format=native_format)
                        else:
                            token_reader = tokenize(reader, cache, int(settings['maximum_object_size']),in_memory=memory_handoff,format=native_format)
                    if token_reader is None and not reader.exists():materialize(plan)
                raw_view(con,reader,ECS_COLUMNS,int(settings['maximum_object_size']),identity_source=source,token_source=token_reader)
            else:
                columns='{' + ', '.join(f'{lit(k)}: {lit(v)}' for k,v in ECS_COLUMNS.items()) + '}'
                run(con,f"CREATE OR REPLACE VIEW raw AS SELECT * FROM read_json({lit(reader)},format='newline_delimited',columns={columns},filename=true,ignore_errors={str(bool(settings.get('ignore_errors',False))).lower()},maximum_object_size={int(settings['maximum_object_size'])})")
        normalize=NORMALIZE_SQL.replace('filename AS src_file',f'{lit(source)} AS src_file').replace('filename, "@timestamp"',f'{lit(source)}, "@timestamp"')
        statement=f'COPY ({normalize}) TO {lit(temporary)} (FORMAT parquet, COMPRESSION {codec}, ROW_GROUP_SIZE 122880)'
        try:
            if quarantine_oversized and plan['bytes']>int(settings['chunk_bytes']):
                # Extended physical records can span gigabytes. Validate directly
                # from the original range, never first copy the whole bad span.
                with read_timing(timings, 'quarantine_seconds'):
                    count,files=quarantine_utf8(reader,cache,plan['key'],int(settings['maximum_object_size']),
                        plan['offset']-plan['bytes'],source,
                        source_range=(plan['offset']-plan['bytes'],plan['bytes']))
                quarantined=True;plan['new_rejected']=count;plan['rejection_files'].extend(files)
                log.warning('Quarantined %s oversized/malformed physical records in %s; source offsets/hashes recorded and original file unchanged',count,source.name)
            if quarantine_oversized and not direct_native and not quarantined:
                materialize(plan)
            prepare_raw()
            if direct_native:
                prefetch.ahead(source,cache,int(settings['maximum_object_size']),plan['offset'],before.st_size,
                               int(settings['chunk_bytes']),native_format,allow_oversized=quarantine_oversized)
            with read_timing(timings, 'parse_normalize_write_seconds'):
                run(con,statement)
        except Exception as exc:
            if quarantined or fmt!='fortigate' or not settings.get('quarantine_invalid_utf8',True) or not any(marker in str(exc) for marker in ('Invalid unicode','Map keys must be unique','CSV Error')):
                raise
            with read_timing(timings, 'quarantine_seconds'):
                if not reader.exists():materialize(plan)
                count,files=quarantine_utf8(reader,cache,plan['key'],int(settings['maximum_object_size']),plan['offset']-plan['bytes'],source)
            quarantined = True
            plan['new_rejected']=count;plan['rejection_files'].extend(files)
            log.warning('Quarantined %s malformed physical-line fragments in %s; source offsets/hashes recorded and original file unchanged',count,source.name)
            if reader.stat().st_size==0:
                columns=', '.join(f'NULL::{dtype} AS \"{name}\"' for name,dtype in ECS_COLUMNS.items())
                run(con,"CREATE OR REPLACE VIEW raw AS SELECT "+columns+", NULL::VARCHAR AS filename WHERE FALSE")
            else:
                prepare_raw()
            with read_timing(timings, 'parse_normalize_write_seconds'):
                run(con,statement)
        finally:
            if token_reader is not None:
                if isinstance(token_reader,TokenBuffer):
                    run(con,'DROP VIEW IF EXISTS raw')
                    run(con,'DROP VIEW IF EXISTS _trace_native_tokens')
                    token_reader.close()
                else:
                    token_reader.unlink(missing_ok=True)
                    token_reader.with_suffix('.meta.json').unlink(missing_ok=True)
        after=source.stat()
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
            temporary.unlink(missing_ok=True)
            raise ValueError('Closed input changed during chunked ingestion; retry when the writer finishes')
        temporary.replace(shard);group=plan['prior']+[shard];commit(plan,group);reader.unlink(missing_ok=True)
        parsed+=plan['bytes']
        log.info('checkpoint %s: %s/%s bytes (%s chunks)',source.name,plan['offset'],before.st_size,len(group))
        progress=work.parent/'progress.json';temporary_progress=progress.with_suffix('.tmp')
        temporary_progress.write_text(json.dumps({'state':'running','stage':'ingest','source':source.name,
              'completed_bytes':plan['offset'],'source_bytes':before.st_size,'chunks':len(group)}),encoding='utf-8')
        temporary_progress.replace(progress)
        if plan['offset']==before.st_size:return group,parsed,plan.get('prior_rejected',0)+plan.get('new_rejected',0),plan['rejection_files']


def ingest(con, cfg: dict, input_dir: Path, work_dir: Path) -> dict:
    files = find_inputs(input_dir, cfg["ingest"]["patterns"])
    if not files:
        raise FileNotFoundError(f"no supported input files under {input_dir}")
    settings = cfg['ingest']
    codec=parquet_codec(settings)
    timings = {}
    columns = "{" + ", ".join(f"{lit(k)}: {lit(v)}" for k, v in ECS_COLUMNS.items()) + "}"
    incremental = settings.get('incremental', False)
    cache = work_dir.parent / 'ingest_cache' if incremental else work_dir / 'shards'
    cache.mkdir(parents=True, exist_ok=True)
    shards, manifest, formats = [], [], {}
    reused = rejected = parsed_bytes = deferred_bytes = reader_rejected = 0
    reader_rejected_bytes = 0
    reader_signature = hashlib.sha256((NORMALIZE_SQL + json.dumps(ECS_COLUMNS, sort_keys=True) + json.dumps(settings,sort_keys=True)).encode()
        + b''.join(Path(__file__).with_name(name).read_bytes() for name in
                   ('adapters.py','fortigate.py','read_cache.py','native_reader.py'))).hexdigest()
    if settings.get('native_fortigate', True):
        import shutil
        native_source = Path(__file__).with_name('native')/'fortigate_tokenize.c'
        compiler = shutil.which('gcc') or shutil.which('clang')
        reader_signature = hashlib.sha256((reader_signature+str(compiler)).encode()+native_source.read_bytes()).hexdigest()
    for number, source in enumerate(files, 1):
        before = source.stat()
        fmt = input_format(source, settings.get('format', 'auto'))
        chunk_bytes=int(settings.get('chunk_bytes',0))
        if incremental and not settings.get('append_only') and chunk_bytes and before.st_size>chunk_bytes and fmt in {'ecs','fortigate'} and source.suffix!='.gz':
            group,processed,invalid,rejection_files=ingest_chunks(con,source,fmt,settings,cache,work_dir,reader_signature,timings)
            reader_rejected+=invalid
            rejected_bytes = sum(json.loads(line)['bytes'] for name in set(rejection_files)
                                 for line in (cache/name).read_text(encoding='utf-8').splitlines())
            reader_rejected_bytes += rejected_bytes
            shards.extend(group);parsed_bytes+=processed;reused+=int(processed==0)
            formats[fmt]=formats.get(fmt,0)+1
            manifest.append({'source':str(source),'size':before.st_size,'format':fmt,'shards':len(group),
                             'rejected_records':invalid,'rejected_bytes':rejected_bytes,'rejection_files':rejection_files})
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
            run(con, f"COPY ({normalize}) TO {lit(temporary)} (FORMAT parquet, COMPRESSION {codec})")
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
    if settings.get('dedupe_events', True):
        selection = 'SELECT * FROM normalized QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY ts_ms)=1'
    else:
        selection = 'SELECT * FROM normalized'
    previous_threads = int(one(con,"SELECT current_setting('threads')")[0])
    dedupe_threads = min(previous_threads, int(cfg['engine'].get('blocking_threads', 4)))
    if dedupe_threads < 1:
        raise ValueError('engine.blocking_threads must be positive')
    run(con, f'SET threads={dedupe_threads}')
    previous_memory=one(con,"SELECT current_setting('memory_limit')")[0]
    blocking_memory=cfg['engine'].get('blocking_memory_limit')
    if blocking_memory:
        run(con,f'SET memory_limit={lit(blocking_memory)}')
    try:
        with read_timing(timings, 'deduplicate_write_seconds'):
            run(con, f"COPY ({selection}) TO {lit(events_path)} (FORMAT parquet, COMPRESSION {codec}, ROW_GROUP_SIZE 122880)")
    finally:
        run(con, f'SET threads={previous_threads}')
        run(con,f'SET memory_limit={lit(previous_memory)}')
    run(con, f'CREATE OR REPLACE VIEW events_all AS SELECT * FROM read_parquet({lit(events_path)})')
    run(con, 'CREATE OR REPLACE VIEW events AS SELECT * FROM events_all WHERE ts_ms IS NOT NULL AND host IS NOT NULL')
    run(con, 'CREATE OR REPLACE VIEW bad_rows AS SELECT * FROM events_all WHERE ts_ms IS NULL OR host IS NULL')
    # Conservative resolution: do not assign an IP that has several observed owners.
    run(con, """CREATE OR REPLACE TABLE ip_host AS
        SELECT ip, min(host) AS host, min(ts_ms) AS first_seen_ms FROM
        (SELECT unnest(host_ips) AS ip, host, ts_ms FROM events WHERE host_ips IS NOT NULL)
        WHERE ip IS NOT NULL GROUP BY ip HAVING count(DISTINCT host) = 1""")
    has_launches=bool(one(con,"SELECT EXISTS (SELECT 1 FROM events WHERE action='process_created' AND proc_pid IS NOT NULL)")[0])
    if has_launches:
        resolved_sql="""
        WITH launches AS (SELECT host, proc_pid, ts_ms, coalesce(proc_entity_id, event_id) AS identity
                          FROM events WHERE action = 'process_created' AND proc_pid IS NOT NULL
                          QUALIFY row_number() OVER (PARTITION BY host, proc_pid, ts_ms ORDER BY event_id) = 1),
        resolved AS (SELECT e.* EXCLUDE (proc_entity_id), coalesce(e.proc_entity_id, p.identity) AS proc_entity_id
                     FROM events e ASOF LEFT JOIN launches p
                     ON e.host = p.host AND e.proc_pid = p.proc_pid AND e.ts_ms >= p.ts_ms)
        SELECT * FROM resolved"""
    else:
        resolved_sql='SELECT * EXCLUDE(proc_entity_id),proc_entity_id FROM events'
    run(con, f"""CREATE OR REPLACE VIEW ev AS
        SELECT e.*, sh.host AS src_host, dh.host AS dst_host FROM ({resolved_sql}) e
        LEFT JOIN ip_host sh ON e.src_ip = sh.ip AND sh.first_seen_ms <= e.ts_ms
        LEFT JOIN ip_host dh ON e.dst_ip = dh.ip AND dh.first_seen_ms <= e.ts_ms""")
    total, bad, tmin, tmax = one(con, 'SELECT count(*), count(*) FILTER (WHERE ts_ms IS NULL OR host IS NULL), min(ts_ms), max(ts_ms) FROM events_all')
    if settings.get('materialize_resolved_events', True) and total - bad >= int(settings.get('resolved_materialize_min_rows', 1000000)):
        resolved_path = work_dir / 'resolved_events.parquet'
        with read_timing(timings, 'resolve_entities_once_seconds'):
            run(con, f"COPY (SELECT * FROM ev) TO {lit(resolved_path)} (FORMAT parquet, COMPRESSION {codec}, ROW_GROUP_SIZE 122880)")
            run(con, f'CREATE OR REPLACE VIEW ev AS SELECT * FROM read_parquet({lit(resolved_path)})')
    run(con, f"COPY (SELECT *, CASE WHEN ts_ms IS NULL AND host IS NULL THEN 'missing_time_and_host' WHEN ts_ms IS NULL THEN 'missing_time' ELSE 'missing_host' END AS quarantine_reason FROM bad_rows) TO {lit(work_dir.parent / 'quarantine.parquet')} (FORMAT parquet)")
    (work_dir.parent / 'ingest_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    raw_count = one(con, 'SELECT count(*) FROM normalized')[0]
    from tracekc.parser_contracts import contracts
    (work_dir.parent/'parser_contracts.json').write_text(json.dumps(contracts(),indent=2),encoding='utf-8')
    profile = dict(zip(('missing_timestamp','missing_host','missing_user','missing_action','missing_network_endpoints'),
                       one(con, """SELECT count(*) FILTER (WHERE ts_ms IS NULL),
                           count(*) FILTER (WHERE host IS NULL),
                           count(*) FILTER (WHERE ts_ms IS NOT NULL AND host IS NOT NULL AND user_name IS NULL),
                           count(*) FILTER (WHERE action IS NULL),
                           count(*) FILTER (WHERE action='network_connection' AND (src_ip IS NULL OR dst_ip IS NULL))
                           FROM events_all""")))
    stats = {'timings':{key:round(value,3) for key,value in timings.items()}, 'dedupe_threads':dedupe_threads,
             'dedupe_memory_limit':blocking_memory or previous_memory,
             'input_files': len(files), 'input_bytes': sum(f.stat().st_size for f in files),
             'events': int(total), 'records_before_deduplication':raw_count, 'quarantined_rows': int(bad), 'parsed_input_bytes': parsed_bytes, 'deferred_tail_bytes': deferred_bytes, 'normalized_shards': len(shards), 'duplicates_removed': raw_count - total,
             'adapter_rejected_records': rejected, 'reader_rejected_records':reader_rejected,
             'reader_rejected_bytes':reader_rejected_bytes, 'reused_files': reused, 'formats': formats,
             **profile, 'valid_events':int(total-bad), 'parser_contract_version':1,
             'ts_min_ms': tmin, 'ts_max_ms': tmax,
             'hosts_with_ips': one(con, 'SELECT count(DISTINCT host) FROM ip_host')[0],
             'parquet_bytes': events_path.stat().st_size,'parquet_compression':codec}
    if total == bad:
        raise ValueError('no valid events with both a timestamp and host; inspect quarantine.parquet')
    log.info('ingested %s events from %s files (%s quarantined)', total, len(files), bad)
    return stats
