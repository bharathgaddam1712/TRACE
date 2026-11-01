"""Byte checkpoints for explicitly append-only, newline-delimited local sources."""
import hashlib
import json
import logging
from pathlib import Path


def anchor(path, offset):
    with path.open('rb') as stream:
        first=stream.read(min(offset,65536))
        stream.seek(max(0,offset-65536));tail=stream.read(min(offset,65536))
    return [hashlib.sha256(first).hexdigest(),hashlib.sha256(tail).hexdigest()]


def prepare(source, cache, work, reader_signature, maximum, chunk_bytes=None, allow_final=False,
            copy_segment=True, allow_oversized=False):
    identity=hashlib.sha256((str(source.resolve())+reader_signature).encode()).hexdigest()
    checkpoint=cache/(identity+'.checkpoint.json')
    before=source.stat();old={};start=0;prior=[]
    if checkpoint.exists():
        candidate=json.loads(checkpoint.read_text(encoding='utf-8'))
        cursor=candidate['offset']
        if before.st_size>=cursor and candidate['inode']==before.st_ino and anchor(source,cursor)==candidate['anchor']:
            prior=[cache/name for name in candidate['shards']]
            if all(p.exists() for p in prior):old=candidate;start=cursor
            else:prior=[]
    end=chunk_end(source,start,before.st_size,maximum,chunk_bytes,allow_final,allow_oversized)
    result={'prior':prior,'checkpoint':checkpoint,'offset':end,'deferred_tail_bytes':before.st_size-end,
            'reader':None,'bytes':end-start,'inode':before.st_ino,'source':source,
            'prior_rejected':old.get('rejected_records',0), 'rejection_files':old.get('rejection_files',[])}
    if end>start:
        segment=work/(identity+'.segment.log')
        result['reader']=segment
        if copy_segment:
            materialize(result)
        result['key']=hashlib.sha256(f'{identity}:{start}:{end}:{anchor(source,end)}'.encode()).hexdigest()
    elif not prior:
        raise ValueError(f'{source.name}: no complete newline-terminated records yet')
    return result


def materialize(plan):
    """Copy a planned byte range only when a parser/quarantine requires a disk file."""
    with plan['source'].open('rb') as stream,plan['reader'].open('wb') as output:
        stream.seek(plan['offset']-plan['bytes']);remaining=plan['bytes']
        while remaining:
            block=stream.read(min(8*1024*1024,remaining))
            if not block:raise ValueError('Source was truncated while being copied')
            output.write(block);remaining-=len(block)


def commit(plan, shards):
    value={'offset':plan['offset'],'inode':plan['inode'],'anchor':anchor(plan['source'],plan['offset']),
           'shards':[p.name for p in shards], 'rejected_records':plan.get('prior_rejected',0)+plan.get('new_rejected',0),
           'rejection_files':plan.get('rejection_files',[])}
    temporary=plan['checkpoint'].with_suffix('.tmp')
    temporary.write_text(json.dumps(value),encoding='utf-8');temporary.replace(plan['checkpoint'])


def chunk_end(source,start,size,maximum,chunk_bytes=None,allow_final=False,allow_oversized=False):
    """Find a physical-record boundary without changing a checkpoint.

    Closed quarantine-capable readers may extend a chunk past an oversized
    record. This changes only framing: the parser limit still rejects that
    record. Never split its continuation into a separately accepted event.
    """
    boundary=min(size,start+chunk_bytes) if chunk_bytes else size
    with source.open('rb') as stream:
        stream.seek(max(start,boundary-maximum-1));tail=stream.read(boundary-stream.tell())
    newline=tail.rfind(b'\n')
    end=max(start,boundary-len(tail)+newline+1) if newline>=0 else start
    if allow_final and boundary==size:
        end=boundary
    if boundary-end>maximum:
        if allow_final and allow_oversized:
            logging.getLogger(__name__).warning(
                '%s: oversized physical record near byte %s; scanning to its end for quarantine',source.name,boundary)
            # The normal bounded tail contains no newline. Search forward with
            # constant memory, not an enlarged parser buffer or guessed boundary.
            with source.open('rb') as stream:
                stream.seek(boundary)
                next_progress=boundary+256*1024*1024
                while boundary<size:
                    block=stream.read(min(1024*1024,size-boundary))
                    if not block:
                        raise ValueError(f'{source.name}: source truncated while finding record boundary')
                    newline=block.find(b'\n')
                    if newline>=0:return boundary+newline+1
                    boundary+=len(block)
                    if boundary>=next_progress:
                        logging.getLogger(__name__).info(
                            'Boundary scan %s: byte %s/%s',source.name,boundary,size)
                        next_progress=boundary+256*1024*1024
            return boundary
        raise ValueError(f'{source.name}: unterminated record exceeds maximum_object_size')
    return end
