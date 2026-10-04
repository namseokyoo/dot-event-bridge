"""User service supervisor. Requires explicit activation; no automatic installation."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from configuration import preflight
BASE=Path(__file__).resolve().parent

def main():
    os.umask(0o077)
    preflight(BASE)
    settings=json.loads((BASE/'ops/bridge.json').read_text())
    import fcntl
    lock=open(BASE/'ops/supervisor.lock','a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    # Generate only nonsecret references; never copy/read the API key.
    tunnel={'config_version':1,'control_plane':{'base_url':'https://api.openai.com','tunnel_id':settings['tunnel_id'],'api_key':'file:'+str(BASE/'ops/runtime-key'),'max_inflight_requests':1},'mcp':{'server_urls':[{'channel':'main','url':'http://127.0.0.1:8787/mcp'}],'extra_headers':{'Authorization':'file:'+str(BASE/'ops/mcp-authorization')},'discovery_extra_headers':{'Authorization':'file:'+str(BASE/'ops/mcp-authorization')},'max_concurrent_requests':1},'health':{'listen_addr':'127.0.0.1:0','url_file':str(BASE/'ops/health-url')},'admin_ui':{'open_browser':False},'log':{'level':'error','format':'json'},'process':{'pid_file':str(BASE/'ops/tunnel.pid')}}
    (BASE/'ops/tunnel.yaml').write_text(json.dumps(tunnel))
    children=[]
    def stop(*a): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
    try:
        # Reject a preexisting listener; do not attach the tunnel to an unrelated service.
        probe=socket.socket(); probe.bind(('127.0.0.1',8787)); probe.close()
        children.append(subprocess.Popen([sys.executable,str(BASE/'bridge.py'),'--config',str(BASE/'ops/bridge.json'),'--data',str(BASE/'data')],stdin=subprocess.DEVNULL,start_new_session=True))
        for attempt in range(100):
            if children[0].poll() is not None: raise RuntimeError('Bridge exited')
            try:
                with socket.create_connection(('127.0.0.1',8787),timeout=.1): pass
                break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('Bridge not ready')
        # Suppress vendor request/error details; health endpoint is the diagnostic surface.
        children.append(subprocess.Popen([str(BASE/'bin/tunnel-client'),'run','--config',str(BASE/'ops/tunnel.yaml')],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True))
        print('service_started',flush=True)
        while all(p.poll() is None for p in children): time.sleep(1)
        return 1
    except KeyboardInterrupt:
        return 0
    finally:
        for p in children:
            if p.poll() is None: os.killpg(p.pid,signal.SIGTERM)
        for p in children:
            try: p.wait(timeout=115)
            except subprocess.TimeoutExpired: os.killpg(p.pid,signal.SIGKILL); p.wait()
        print('service_stopped',flush=True)

if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        print('startup_or_runtime_failed; inspect nonsecret health and activation prerequisites',file=sys.stderr)
        sys.exit(1)
