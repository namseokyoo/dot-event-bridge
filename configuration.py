"""Fail-closed operating configuration validation. Does not read runtime credentials."""
import json
import math
import os
from pathlib import Path
import stat

def private_file(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError('Private regular owned file required')

def validate_config(config):
    import re
    if not re.fullmatch(r'tunnel_[A-Za-z0-9_-]{8,128}',config.get('tunnel_id','')): raise ValueError('Tunnel ID required')
    principals=config['principals']
    if not principals: raise ValueError('No approved principals')
    ids=set(); hashes=set(); senders=set()
    for p in principals:
        if p['id'] in ids or p['token_sha256'] in hashes: raise ValueError('Duplicate principal')
        if not p['id'] or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in p['id']): raise ValueError('Invalid ID')
        if len(bytes.fromhex(p['token_sha256'])) != 32: raise ValueError('Invalid digest')
        if type(p.get('expires_at')) not in (int,float) or not math.isfinite(p['expires_at']) or p['expires_at']<=0: raise ValueError('Explicit expiry required')
        ids.add(p['id']); hashes.add(p['token_sha256'])
        if p['role']=='sender':
            if p.get('require_subscription') is not True: raise ValueError('Active subscriber requirement must be enabled')
            ops=p.get('allowed_operations',[])
            approvals=p.get('approval_required_operations',[])
            if not isinstance(ops,list) or not isinstance(approvals,list) or any(not isinstance(x,str) or not x for x in approvals): raise ValueError('Operation lists required')
            if not ops or '*' in ops or any(not isinstance(x,str) or not x for x in ops): raise ValueError('Explicit operations required')
            if not set(p.get('approval_required_operations',[])) <= set(ops): raise ValueError('Unknown approval operation')
            senders.add(p['id'])
        elif p['role']!='consumer': raise ValueError('Invalid role')
    for p in principals:
        if p['role']=='consumer' and (not p.get('senders') or not set(p['senders']) <= senders): raise ValueError('Explicit known sender scope required')
    if config.get('callback_hosts') != ['connectors.api.openai.com']: raise ValueError('Only verified callback allowed')
    for name,value in config.get('limits',{}).items():
        ceilings={'requests_per_minute':600,'messages_per_minute':60,'pending_per_sender':1000,'max_messages':100000,'subscriptions_per_consumer':32,'processing_timeout':3600}
        if name not in ceilings or type(value)!=int or not 1<=value<=ceilings[name]: raise ValueError('Invalid limit')
    return config

def preflight(base):
    info=(base/'ops').lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077: raise ValueError('Private owned ops directory required')
    cfg=base/'ops/bridge.json'
    marker=base/'ops/activation.json'
    for path in (cfg,marker,base/'ops/runtime-key',base/'ops/mcp-authorization'):
        private_file(path)
    approval=json.loads(marker.read_text())
    if not all(approval.get(k) is True for k in ('runtime_key_rotated','targets_approved','production_authorized')):
        raise ValueError('Operator activation approvals missing')
    validate_config(json.loads(cfg.read_text()))
    return True
