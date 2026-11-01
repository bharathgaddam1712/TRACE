"""Optional compiled lexer; DuckDB regex reading remains the portable fallback."""
from functools import lru_cache
from dataclasses import dataclass
import io
import hashlib
import json
import logging
from pathlib import Path
import re
import shutil
import subprocess
import sys

log = logging.getLogger(__name__)


@dataclass
class TokenBuffer:
    stream: io.BytesIO
    max_line_bytes: int
    relation: object = None
    format: str = 'csv'

    def close(self):
        self.relation = None
        self.stream.close()


@lru_cache(maxsize=4)
def executable(cache: str):
    source = Path(__file__).with_name('native')/'fortigate_tokenize.c'
    compiler = shutil.which('gcc') or shutil.which('clang')
    if compiler is None or not source.exists():
        return None
    digest = hashlib.sha256(source.read_bytes()+compiler.encode()).hexdigest()[:20]
    target = Path(cache)/('fortigate-'+digest+('.exe' if sys.platform=='win32' else ''))
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        temporary = target.with_name(target.stem+'.building'+target.suffix)
        try:
            subprocess.run([compiler,'-O3','-std=c99',str(source),'-o',str(temporary)],
                           check=True,capture_output=True,timeout=60)
            temporary.replace(target)
        except (OSError, subprocess.SubprocessError):
            temporary.unlink(missing_ok=True)
            log.warning('Native lexer build unavailable; retaining DuckDB regex reader')
            return None
    return target


def field_names():
    from tracekc import fortigate
    return sorted(set(re.findall(r"kv\['([^']+)'\]", Path(fortigate.__file__).read_text(encoding='utf-8'))))


def tokenize(source: Path, cache: Path, maximum: int, *, in_memory=False, offset=0, length=None, destination=None, format='csv'):
    binary = executable(str(cache/'native'))
    if binary is None:
        return None
    if format not in {'csv','json'}:raise ValueError('Native format must be csv or json')
    target = destination or source.with_suffix('.tokens.'+format)
    try:
        command=[str(binary),','.join(field_names()),str(maximum)]
        if length is not None or format=='json':command.append(str(length if length is not None else 18446744073709551615))
        if format=='json':command.append('json')
        with source.open('rb',buffering=0) as reader:
            reader.seek(offset)
            if in_memory:
                result=subprocess.run(command,stdin=reader,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
            else:
                with target.open('wb') as writer:
                    result=subprocess.run(command,stdin=reader,stdout=writer,stderr=subprocess.PIPE,check=False)
        if result.returncode == 65:
            if not in_memory:target.unlink(missing_ok=True)
            return None
        if result.returncode:
            raise ValueError(result.stderr.decode('utf-8',errors='replace') or f'Native lexer failed: {result.returncode}')
        match=re.fullmatch(rb'max_csv_line_bytes=(\d+)',result.stderr)
        if match is None:
            raise ValueError('Native lexer did not report a record-size bound')
        if in_memory:
            return TokenBuffer(io.BytesIO(result.stdout),int(match[1]),format=format)
        target.with_suffix('.meta.json').write_text(json.dumps({'max_line_bytes':int(match[1]),'format':format}),encoding='utf-8')
        return target
    except BaseException:
        if not in_memory:target.unlink(missing_ok=True)
        raise


class TokenPrefetch:
    """One disk-backed chunk ahead; checkpoints remain owned by the ingest thread."""
    def __init__(self, enabled):
        from concurrent.futures import ThreadPoolExecutor
        self.pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='trace-lexer') if enabled else None
        self.pending=None

    def __enter__(self):
        return self

    def get(self, source,cache,maximum,**kwargs):
        key=(kwargs.get('offset',0),kwargs.get('length'))
        if self.pending is not None and self.pending[0]==key:
            _,future=self.pending;self.pending=None
            return future.result()
        return tokenize(source,cache,maximum,**kwargs)

    def ahead(self,source,cache,maximum,start,size,chunk_bytes,format,*,allow_oversized=False):
        if self.pool is None or self.pending is not None or start>=size:return
        from tracekc.read_cache import chunk_end
        try:
            end=chunk_end(source,start,size,maximum,chunk_bytes,True)
        except ValueError as exc:
            if allow_oversized and 'unterminated record exceeds maximum_object_size' in str(exc):
                return  # Foreground quarantine owns oversized ranges, not speculative lexing.
            raise
        if end<=start:return
        target=cache/f'prefetch-{start}-{end}.tokens.{format}'
        future=self.pool.submit(tokenize,source,cache,maximum,offset=start,length=end-start,
                                destination=target,format=format)
        self.pending=((start,end-start),future)

    def __exit__(self,*exc):
        if self.pool is None:return
        self.pool.shutdown(wait=True,cancel_futures=True)
        if self.pending is not None:
            future=self.pending[1]
            if not future.cancelled():
                try:
                    result=future.result()
                    if isinstance(result,Path):
                        result.unlink(missing_ok=True);result.with_suffix('.meta.json').unlink(missing_ok=True)
                except Exception:
                    pass  # The foreground failure takes precedence; no checkpoint was published.
        self.pending=None
