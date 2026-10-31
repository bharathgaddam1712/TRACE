"""Explicit supported-parser contracts and normalized detection prerequisites."""


def contracts():
    from tracekc.ingest import ECS_COLUMNS
    return {
        'version':1,
        'normalized_required':['ts_ms','host'],
        'formats':{
            'ecs':{'input':'newline-delimited JSON objects with explicit ECS columns',
                   'timestamp':'@timestamp with timezone', 'host':'host.name or host.hostname',
                   'unknown_fields':'not projected; original source remains authoritative',
                   'invalid_records':'strict failure by default; do not silently enable ignore_errors'},
            'fortigate':{'input':'FortiGate date/time and key=value records',
                        'timestamp':'eventtime nanoseconds, or date + time + tz',
                        'host':'internal endpoint for traffic; firewall device for authentication',
                        'invalid_records':'bounded byte-span quarantine on supported reader failures; parsed missing time/host quarantined'},
            'csv':{'input':'header with dotted ECS names or documented aliases',
                   'timestamp':'timestamp/time/@timestamp', 'host':'host/hostname/host.name',
                   'invalid_records':'row conversion failures are counted with source line/reason; missing required fields quarantined'},
            'syslog':{'input':'ISO8601-timestamped syslog with host; no inferred year',
                      'timestamp':'explicit ISO8601 timestamp', 'host':'host token',
                      'invalid_records':'malformed/oversized lines rejected with diagnostics; generic messages do not become process telemetry'}},
        'ecs_projection':ECS_COLUMNS,
        'noise_policy':{
            'duplicate_event_ids':'deduplicated, counts retained',
            'malformed_bytes':'quarantine/account; never treated as events',
            'missing_required_fields':'quarantine.parquet',
            'recurrent_alerts':'retained findings, excluded from promotion/linking according to configuration',
            'benign_or_unknown':'retained normalized telemetry; not deleted based on model opinion',
            'limitation':'No parser detects all noise or supports every vendor format. Schema support is not attack coverage.'}}
