"""Exclusive owner-invoked runtime credential receiver. Never prints its input."""
import fcntl
import json
import os
from pathlib import Path
import sys
from configuration import private_file

def receive(stream,base):
    os.umask(0o077)
    ops=base/'ops'
    ops.mkdir(mode=0o700,exist_ok=True)
    if ops.is_symlink() or ops.stat().st_uid!=os.getuid() or ops.stat().st_mode & 0o077: raise ValueError('Unsafe directory')
    with (ops/'supervisor.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        raw=stream.read(8193)
        if len(raw)>8192: raise ValueError('Oversize')
        value=json.loads(raw)
        if set(value)!={'key'} or not isinstance(value['key'],str): raise ValueError('Invalid input')
        key=value['key']
        if not 16<=len(key)<=4096 or any(c.isspace() for c in key): raise ValueError('Invalid shape')
        fd=os.open(ops/'runtime-key',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f: f.write(key+'\n')

if __name__=='__main__':
    try: receive(sys.stdin.buffer,Path(__file__).resolve().parent)
    except Exception: raise SystemExit('Save refused; no details logged.')
    print('Saved; service not started.')
