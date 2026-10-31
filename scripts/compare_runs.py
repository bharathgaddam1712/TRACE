"""Compare pipeline totals and order-independent checksums of every normalized row."""
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
    result={'all_passed':all(checks.values()),'checks':checks,
            'row_checksum_method':'Count, sum and XOR of DuckDB 64-bit row hashes over all normalized columns; probabilistic multiset comparison.',
            'reference_seconds':a['timings']['total_wall_seconds'],
            'candidate_seconds':b['timings']['total_wall_seconds']}
    write_json(candidate/'quality_comparison.json',result)
    print(json.dumps(result,indent=2))
    return 0 if result['all_passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
