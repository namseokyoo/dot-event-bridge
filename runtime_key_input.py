"""Owner-run hidden local input, encrypted SSH stdin, no secret command arguments."""
import argparse
import getpass
import json
import os
from pathlib import PurePosixPath
import resource
import shlex
import subprocess
import sys
import termios
import warnings

def hidden():
    if not sys.stdin.isatty() or not sys.stderr.isatty(): raise ValueError('Local terminal required')
    fd=os.open('/dev/tty',os.O_RDWR|os.O_NOCTTY)
    try: termios.tcgetattr(fd)
    finally: os.close(fd)
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        return getpass.getpass('New dedicated runtime key (hidden): ').strip()

def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    ap=argparse.ArgumentParser()
    ap.add_argument('--ssh-host',required=True); ap.add_argument('--remote-dir',required=True)
    args=ap.parse_args()
    if args.ssh_host.startswith('-') or any(c.isspace() for c in args.ssh_host): raise ValueError('Invalid SSH alias')
    remote=PurePosixPath(args.remote_dir)
    if not remote.is_absolute() or '..' in remote.parts: raise ValueError('Absolute directory required')
    if not sys.stdin.isatty() or not sys.stderr.isatty(): raise ValueError('Local terminal required')
    print('Owner only. Revoke the exposed/old key first; close all key-display browser windows.')
    print('The new key will be saved only in the specified server project. No service starts.')
    if input('Confirm scope, old-key revocation, and target. Type YES: ')!='YES': return 1
    key=hidden()
    if not 16<=len(key)<=4096 or any(c.isspace() for c in key): raise ValueError('Invalid key shape')
    if input('Send using existing SSH authentication? Type YES: ')!='YES': return 1
    command='python3 '+shlex.quote(str(remote/'runtime_key_receive.py'))
    result=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',args.ssh_host,command],input=json.dumps({'key':key}).encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
    if result.returncode: raise ValueError('Save unconfirmed')
    print('New runtime key saved. No process started. Do not share key or screenshots.')
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except (Exception,KeyboardInterrupt):
        raise SystemExit('Stopped or save unconfirmed. No secret details logged. Review status before retrying.')
