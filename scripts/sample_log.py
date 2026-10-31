"""Copy a bounded, line-aligned prefix without modifying the source; record provenance."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def sample(source, target, size_bytes):
    source, target = Path(source).resolve(), Path(target).resolve()
    if source == target or size_bytes <= 0:
        raise ValueError('Use a distinct output and positive size')
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    count = size = 0
    sensitive = {}
    pattern = re.compile(rb'(?i)\b(password|passwd|secret|api_key|access_token|authorization|cookie)\s*=')
    initial = source.stat()
    with source.open('rb') as src, target.open('xb') as dst:
        while size < size_bytes:
            line = src.readline(16 * 1024 * 1024 + 1)
            if not line:
                break
            if len(line) > 16 * 1024 * 1024 or not line.endswith(b'\n'):
                raise ValueError('Oversized or incomplete record; output is not publishable')
            line.decode('utf-8', errors='strict')
            for match in pattern.finditer(line):
                key = match[1].decode().lower()
                sensitive[key] = sensitive.get(key, 0) + 1
            dst.write(line)
            digest.update(line)
            size += len(line)
            count += 1
    final = source.stat()
    if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
        raise ValueError('Source changed during extraction')
    report = {'selection': 'contiguous file prefix, complete lines; not a random or representative sample',
              'source_name': source.name, 'source_bytes': initial.st_size, 'offset': 0,
              'bytes': size, 'records': count, 'sha256': digest.hexdigest(),
              'sensitive_field_counts': sensitive,
              'privacy_note': 'Pattern scan is not a guarantee of anonymity; network identifiers remain.'}
    target.with_suffix(target.suffix + '.manifest.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--mib', type=int, default=500)
    args = parser.parse_args()
    print(json.dumps(sample(args.input, args.output, args.mib * 1024 * 1024), indent=2))
