"""Publish compact, non-secret benchmark summaries; never commit all event evidence."""
import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',required=True)
    parser.add_argument('--optimized',required=True)
    parser.add_argument('--temporal',nargs='+',required=True)
    parser.add_argument('--out',default='docs/benchmarks/firex-500mib.json')
    args = parser.parse_args()
    before,after = read(args.baseline),read(args.optimized)
    if before['ingest']['input_bytes'] != after['ingest']['input_bytes']:
        raise ValueError('Cannot compare different input sizes')
    def compact(report):
        return {key:report[key] for key in ('timings','peak_process_tree_rss_gb','output','signals')}
    tree = hashlib.sha256()
    for path in sorted([*Path('src').rglob('*.py'),*Path('configs').glob('*.yaml'),Path('web/app.js'),Path('pyproject.toml')]):
        tree.update(path.as_posix().encode()+b'\0'+path.read_bytes())
    result = {'sample':read('data/benchmarks/firex-500mib.log.manifest.json'),
              'baseline_commit':'668033f','tested_source_sha256':tree.hexdigest(),
              'comparison':'sequential cached ingestion runs, same 3GB DuckDB budget and four threads; single trial, not a confidence interval',
              'baseline':compact(before),'optimized':compact(after),
              'detection_counts_equal':before['detect']['detections_by_rule']==after['detect']['detections_by_rule'],
              'events':after['ingest']['events'],'base_rules_evaluated':after['detect']['base_rules_evaluated'],
              'temporal':[read(path) for path in args.temporal],
              'notes':['Cold ingestion runs are not compared because OS-cache state and background activity differed.',
                       'Counts alone do not prove detection/correlation accuracy; independent attack ground truth is unavailable.',
                       'Temporal scores use a capped chronological subset, not all interactions in the 500 MiB file.']}
    path = Path(args.out);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(path)


if __name__ == '__main__':
    main()
