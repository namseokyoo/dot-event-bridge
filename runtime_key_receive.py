"""Owner-invoked atomic runtime credential receiver; no secret output."""
import fcntl
import grp
import pwd
import json
import os
from pathlib import Path
import secrets
import stat
import sys


def checked_directory(path, private=False):
    for part in [path]+list(path.parents):
        info=part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode & 0o002:
            raise ValueError('Unsafe parent directory')
        if info.st_mode & 0o020:
            # A private primary group containing only this owner is not a second writer.
            owner=pwd.getpwuid(os.getuid())
            group=grp.getgrgid(info.st_gid)
            others=[u for u in pwd.getpwall() if u.pw_gid==info.st_gid and u.pw_uid not in (0,os.getuid())]
            if info.st_uid!=os.getuid() or info.st_gid!=owner.pw_gid or others or set(group.gr_mem)-{owner.pw_name,'root'}:
                raise ValueError('Untrusted group-writable parent')
    info=path.lstat()
    if private and (info.st_uid!=os.getuid() or info.st_mode & 0o077):
        raise ValueError('Private owned directory required')


def receive(stream,base):
    os.umask(0o077)
    checked_directory(base)
    raw=stream.read(8193)
    if len(raw)>8192: raise ValueError('Oversize')
    value=json.loads(raw)
    if set(value)!={'key','confirmed'} or value['confirmed'] is not True or not isinstance(value['key'],str):
        raise ValueError('Explicit submission required')
    key=value['key']
    if not 16<=len(key)<=4096 or any(c.isspace() for c in key): raise ValueError('Invalid shape')
    ops=base/'ops'
    ops.mkdir(mode=0o700,exist_ok=True)
    checked_directory(ops,private=True)
    lock_fd=os.open(ops/'supervisor.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock_fd,'a') as lock:
        info=os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077: raise ValueError('Unsafe lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        destination=ops/'runtime-key'
        if destination.exists() or destination.is_symlink():
            info=destination.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077: raise ValueError('Unsafe destination')
        staging=ops/('.runtime-key-'+secrets.token_hex(12))
        try:
            fd=os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as output:
                output.write(key+'\n'); output.flush(); os.fsync(output.fileno())
            os.replace(staging,destination)
            directory_fd=os.open(ops,os.O_RDONLY|os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            if staging.exists(): staging.unlink()

if __name__=='__main__':
    try: receive(sys.stdin.buffer,Path(__file__).absolute().parent)
    except Exception: raise SystemExit('Save refused or unconfirmed; no secret details logged.')
    print('Saved; service not started.')
