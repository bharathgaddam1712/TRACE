"""Losslessly gzip the demo input for practical Git LFS distribution."""
import gzip
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            result.update(chunk)
    return result.hexdigest()


if __name__ == '__main__':
    source = Path('data/benchmarks/firex-500mib.log')
    target = source.with_suffix('.log.gz')
    with source.open('rb') as src, target.open('xb') as dst:
        with gzip.GzipFile(filename='',mode='wb',compresslevel=6,mtime=0,fileobj=dst) as compressed:
            shutil.copyfileobj(src,compressed,length=1024*1024)
    manifest_path = source.with_suffix('.log.manifest.json')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if digest(source) != manifest['sha256']:
        raise ValueError('Input changed since extraction')
    manifest.update(distribution_file=target.name,distribution_bytes=target.stat().st_size,
                    distribution_sha256=digest(target),distribution='lossless gzip; decompress before running the chunked-reader demo')
    manifest_path.write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({key:value for key,value in manifest.items() if key.startswith('distribution')},indent=2))
