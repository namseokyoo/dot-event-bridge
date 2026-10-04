"""Offline owner operations. Refuses writes while the bridge owns the database."""
import argparse
import fcntl
import json
from pathlib import Path
import sqlite3
from bridge import Bridge,Callback,Fault

BASE=Path(__file__).resolve().parent

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=['status','approve','retry'])
    ap.add_argument('--id')
    ap.add_argument('--redeliver-reviewed',action='store_true',help='Owner confirmed external-effect reconciliation; permits a new event for an already delivered request')
    args=ap.parse_args()
    data=BASE/'data'
    if args.action=='status':
        c=sqlite3.connect('file:'+str(data/'bridge.sqlite3')+'?mode=ro',uri=True)
        # Aggregate states only: no body, principal, URL, or credential output.
        for table in ('messages','outbox'):
            print(table,json.dumps(c.execute('SELECT state,count(*) FROM '+table+' GROUP BY state').fetchall()))
        print('active_subscriptions',c.execute('SELECT count(*) FROM subscriptions WHERE active=1 AND expires>unixepoch()').fetchone()[0])
        return
    if not args.id: ap.error('--id required')
    with (data/'instance.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        config=json.loads((BASE/'ops/bridge.json').read_text())
        b=Bridge(str(data/'bridge.sqlite3'),config['principals'],Callback(config['callback_hosts']),config.get('limits'))
        try:
            if args.action=='approve': b.approve_local(args.id)
            else:
                with b.lock,b.db:
                    row=b.db.execute('SELECT o.state,m.state,m.approved,s.active,s.expires FROM outbox o JOIN messages m ON m.id=o.message JOIN subscriptions s ON s.id=o.subscription WHERE o.id=?',(args.id,)).fetchone()
                    import time
                    if not row or (row[0] not in ('dead','cancelled') and not (row[0]=='delivered' and args.redeliver_reviewed)) or row[1]!='received' or not row[2] or not row[3] or row[4]<=time.time(): raise Fault('Not eligible for explicit retry')
                    if row[0]=='delivered':
                        import uuid
                        from bridge import iso
                        event=json.loads(b.db.execute('SELECT payload FROM outbox WHERE id=?',(args.id,)).fetchone()[0])
                        event['eventId']='evt_'+uuid.uuid4().hex; event['timestamp']=iso(time.time())
                        b.db.execute("UPDATE outbox SET id=?,payload=?,state='pending',attempts=0,next=0 WHERE id=?",(event['eventId'],json.dumps(event),args.id))
                    else:
                        b.db.execute("UPDATE outbox SET state='pending',attempts=0,next=0 WHERE id=?",(args.id,))
            print('operator_change_saved')
        finally: b.db.close()

if __name__=='__main__':
    try: main()
    except Exception:
        raise SystemExit('Operation refused or unavailable; stop service and check prerequisites. No secret details logged.')
