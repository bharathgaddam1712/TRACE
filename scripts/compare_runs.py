"""Compare totals, normalized-row checksums and complete incident payloads."""
import argparse
import json
from pathlib import Path

import duckdb

from tracekc.materialize import write_json


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference',required=True)
    parser.add_argument('--candidate',required=True)
    args=parser.parse_args()
    reference,candidate=Path(args.reference),Path(args.candidate)
    a=json.loads((reference/'run_metrics.json').read_text(encoding='utf-8'))
    b=json.loads((candidate/'run_metrics.json').read_text(encoding='utf-8'))
    keys=['events','records_before_deduplication','duplicates_removed','valid_events',
          'quarantined_rows','reader_rejected_records','reader_rejected_bytes']
    checks={f'ingest.{key}':a['ingest'].get(key)==b['ingest'].get(key) for key in keys}
    for key in ('detections_by_source','detections_by_rule'):
        checks['detect.'+key]=a['detect'][key]==b['detect'][key]
    checks['signals']=a['signals']==b['signals']
    checks['output']=a['output']==b['output']
    with duckdb.connect() as con:
        con.execute("SET memory_limit='512MB'")
        con.execute('SET threads=2')
        summaries=[]
        for root in (reference,candidate):
            path=str(root/'work'/'events.parquet')
            cols=[r[0] for r in con.execute('DESCRIBE SELECT * FROM read_parquet(?)',[path]).fetchall()]
            projection=','.join('"'+c.replace('"','""')+'"' for c in cols)
            summaries.append(con.execute(f'SELECT count(*),sum(hash({projection})::HUGEINT),bit_xor(hash({projection})) FROM read_parquet(?)',[path]).fetchone())
    checks['all_normalized_rows_checksum']=summaries[0]==summaries[1]
    incident_sets=[]
    for root in (reference,candidate):
        incident_sets.append(sorted(row['fingerprint'] for row in json.loads((root/'index.json').read_text(encoding='utf-8'))))
    checks['incident_evidence_fingerprints']=incident_sets[0]==incident_sets[1]
    # Counts and fingerprints can match while any_value reductions select different
    # evidence or graph identities. Treat that as a failed quality gate.
    payloads_equal = True
    mismatched = []
    files_a={p.name for p in (reference/'incidents').glob('*.json')}
    files_b={p.name for p in (candidate/'incidents').glob('*.json')}
    for name in sorted(files_a | files_b):
        if name not in files_a or name not in files_b:
            payloads_equal=False; mismatched.append(name); continue
        left=json.loads((reference/'incidents'/name).read_text(encoding='utf-8'))
        right=json.loads((candidate/'incidents'/name).read_text(encoding='utf-8'))
        if left != right:
            payloads_equal=False; mismatched.append(name)
    checks['complete_incident_payloads']=payloads_equal
    result={'all_passed':all(checks.values()),'checks':checks,
            'row_checksum_method':'Count, sum and XOR of DuckDB 64-bit row hashes over all normalized columns; probabilistic multiset comparison.',
            'mismatched_incident_files':mismatched,
            'reference_seconds':a['timings']['total_wall_seconds'],
            'candidate_seconds':b['timings']['total_wall_seconds']}
    write_json(candidate/'quality_comparison.json',result)
    print(json.dumps(result,indent=2))
    return 0 if result['all_passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
