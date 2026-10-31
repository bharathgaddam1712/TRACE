"""Native, parallel DuckDB FortiGate key=value reader. No Python loop over millions of lines."""
from tracekc.engine import run
from tracekc.sigma import lit


def raw_view(con, source, columns, maximum, identity_source=None):
    identity = lit(str(identity_source or source))
    pattern = r'([a-zA-Z0-9_]+)=("(?:[^"\\]|\\.)*"|[^ \r\n]+)'
    parsed = f"""SELECT line, filename,
        map_from_entries(list_transform(regexp_extract_all(line, {lit(pattern)}),
          lambda x: struct_pack(key := split_part(x, '=', 1),
            value := trim(substr(x, length(split_part(x, '=', 1)) + 2), '"')))) AS kv
        FROM read_csv({lit(source)}, columns={{'line':'VARCHAR'}}, delim=chr(31), quote='', escape='',
          header=false, filename=true, auto_detect=false, strict_mode=false, new_line='\\n', max_line_size={maximum}, compression='auto', parallel=true) WHERE length(trim(line)) > 0"""
    ip = "CASE WHEN kv['srcintfrole'] IN ('lan','dmz') OR is_internal(kv['srcip']) THEN kv['srcip'] WHEN kv['dstintfrole'] IN ('lan','dmz') OR is_internal(kv['dstip']) THEN kv['dstip'] END"
    auth = "kv['action'] IN ('login','logout','ssl-login-fail','tunnel-up','tunnel-down') OR lower(coalesce(kv['logdesc'],'')) LIKE '%login%'"
    action = f"CASE WHEN {auth} THEN 'user_logon' WHEN kv['subtype']='dns' THEN 'dns_query' WHEN kv['type']='traffic' OR kv['subtype'] IN ('ips','app-ctrl','webfilter','virus') THEN 'network_connection' ELSE coalesce(kv['action'],'firewall_event') END"
    outcome = "CASE WHEN kv['status'] IN ('failed','failure') OR kv['action'] IN ('deny','blocked','block','dropped','ssl-login-fail') THEN 'failure' WHEN kv['status'] IN ('success','succeeded') OR kv['action'] IN ('accept','pass','close','tunnel-up') THEN 'success' ELSE 'unknown' END"
    severity = "CASE kv['level'] WHEN 'emergency' THEN 10 WHEN 'alert' THEN 9 WHEN 'critical' THEN 8 WHEN 'error' THEN 7 WHEN 'warning' THEN 5 ELSE 3 END"
    expr = {
        '@timestamp': "coalesce(CAST(to_timestamp(try_cast(kv['eventtime'] AS DOUBLE)/1000000000) AS VARCHAR), kv['date'] || 'T' || kv['time'] || coalesce(kv['tz'],'+0000'))",
        'message': "concat_ws('; ', kv['attack'], kv['logdesc'], kv['msg'], kv['reason'])",
        'event': f"struct_pack(id := md5({identity} || line), kind := CASE WHEN kv['subtype'] IN ('ips','virus') THEN 'alert' ELSE 'event' END, category := [CASE WHEN {auth} THEN 'authentication' ELSE 'network' END], action := {action}, outcome := {outcome}, severity := {severity}, dataset := 'fortigate.' || coalesce(kv['subtype'],'unknown'), module := 'fortigate')",
        'host': f"struct_pack(name := CASE WHEN {auth} THEN coalesce(kv['devname'],kv['devid']) ELSE coalesce({ip},kv['devname'],kv['devid']) END, ip := CASE WHEN {auth} THEN []::VARCHAR[] ELSE [({ip})] END)",
        'user': "struct_pack(name := kv['user'], domain := kv['domain'])",
        'source': "struct_pack(ip := kv['srcip'], port := try_cast(kv['srcport'] AS INTEGER))",
        'destination': "struct_pack(ip := kv['dstip'], port := try_cast(kv['dstport'] AS INTEGER), domain := coalesce(kv['hostname'],kv['qname'],kv['dstname']))",
        'network': "struct_pack(transport := CASE kv['proto'] WHEN '6' THEN 'tcp' WHEN '17' THEN 'udp' WHEN '1' THEN 'icmp' END, direction := CASE WHEN kv['srcintfrole']='wan' THEN 'inbound' WHEN kv['dstintfrole']='wan' THEN 'outbound' ELSE 'internal' END, protocol := lower(kv['service']), bytes := try_cast(kv['sentbyte'] AS BIGINT))",
        'dns': "struct_pack(question := struct_pack(name := CASE WHEN kv['subtype']='dns' THEN coalesce(kv['qname'],kv['hostname']) END, type := kv['qtype']), response_code := kv['rcode'])",
        'rule': "struct_pack(id := coalesce(kv['attackid'],kv['logid']), name := coalesce(kv['attack'],kv['logdesc']), severity := CASE kv['level'] WHEN 'alert' THEN 'high' WHEN 'critical' THEN 'critical' WHEN 'emergency' THEN 'critical' WHEN 'error' THEN 'high' WHEN 'warning' THEN 'medium' ELSE 'low' END)",
        'file': "struct_pack(name := coalesce(kv['filename'],kv['file']), path := kv['filename'], size := try_cast(kv['filesize'] AS BIGINT))",
    }
    projections = [f'CAST({expr[name]} AS {dtype}) AS "{name}"' if name in expr else f'NULL::{dtype} AS "{name}"' for name,dtype in columns.items()]
    run(con, 'CREATE OR REPLACE VIEW raw AS WITH parsed AS ('+parsed+') SELECT '+', '.join(projections)+', filename FROM parsed')
