import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from bridge import Bridge,Callback,Fault
from configuration import preflight,validate_config

P={'id':'agent-a','role':'sender','token_sha256':hashlib.sha256(b'synthetic-only-a').hexdigest(),'allowed_operations':['read','change'],'approval_required_operations':['change']}
Q={'id':'consumer','role':'consumer','senders':['agent-a'],'token_sha256':hashlib.sha256(b'synthetic-only-q').hexdigest()}
R={'id':'agent-b','role':'sender','token_sha256':hashlib.sha256(b'synthetic-only-b').hexdigest(),'allowed_operations':['read']}

class Operations(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=str(Path(self.tmp.name)/'state.db')
        self.b=Bridge(self.path,[P,Q,R],Callback([]))
    def tearDown(self): self.b.db.close(); self.tmp.cleanup()
    def send(self,key='one',operation='read',who=P):
        return self.b.enqueue(who,{'idempotency_key':key,'operation':operation,'body':'Synthetic data only'})['id']
    def test_approval_cannot_be_self_granted(self):
        mid=self.send(operation='change')
        self.assertEqual(self.b.get_message(Q,mid)['processing_state'],'awaiting_approval')
        self.assertEqual(self.b.db.execute('select count(*) from outbox').fetchone()[0],0)
        for p in (P,Q):
            with self.assertRaises(Fault): self.b.save_result(p,{'message_id':mid,'state':'completed','result':'not allowed'})
        with self.b.db:
            self.b.db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,1)',('sub_synthetic','consumer','agent-a','https://example.invalid/callback','synthetic-only-unused',None,0,time.time()+60))
        self.b.approve_local(mid)
        self.b.save_result(Q,{'message_id':mid,'state':'completed','result':'Synthetic approved result'})
    def test_undeclared_operation_denied(self):
        with self.assertRaises(Fault): self.send(operation='shell')
    def test_cancel_prevents_later_completion_and_cross_sender_access(self):
        mid=self.send()
        with self.assertRaises(Fault): self.b.cancel(R,mid)
        self.b.cancel(P,mid); self.b.cancel(P,mid)
        with self.assertRaises(Fault): self.b.save_result(Q,{'message_id':mid,'state':'completed','result':'late'})
        with self.assertRaises(Fault): self.b.get_message(R,mid)
    def test_pending_and_rate_limits_preserve_idempotency(self):
        self.b.limits['pending_per_sender']=1
        mid=self.send()
        self.assertEqual(self.send(),mid)
        with self.assertRaises(Fault): self.send('two')
        self.b.limits['requests_per_minute']=1
        self.b.rate(P)
        self.b.db.close(); self.b=Bridge(self.path,[P,Q,R],Callback([]),{'requests_per_minute':1})
        with self.assertRaises(Fault): self.b.rate(P)
        self.b.rate(R)
    def test_processing_crash_requires_review_without_auto_replay(self):
        mid=self.send(); self.b.save_result(Q,{'message_id':mid,'state':'processing'})
        with self.b.db: self.b.db.execute('update messages set updated=? where id=?',(time.time()-1000,mid))
        self.b.db.close(); self.b=Bridge(self.path,[P,Q,R],Callback([])); self.b.tick()
        self.assertEqual(self.b.get_message(Q,mid)['processing_state'],'awaiting_approval')
        with self.assertRaises(Fault): self.b.save_result(Q,{'message_id':mid,'state':'completed','result':'late'})
    def test_storage_limit(self):
        self.b.limits['max_messages']=1; self.send()
        with self.assertRaises(Fault): self.send('two',who=R)
    def test_config_and_activation_fail_closed(self):
        with self.assertRaises((OSError,ValueError)): preflight(Path(self.tmp.name))
        cfg={'tunnel_id':'tunnel_synthetic000','principals':[P,Q,R],'callback_hosts':['connectors.api.openai.com']}
        cfg['principals']=[dict(x,expires_at=4102444800,**({'require_subscription':True} if x['role']=='sender' else {})) for x in cfg['principals']]
        validate_config(cfg)
        cfg['principals']=[dict(P,allowed_operations=['*']),Q]
        with self.assertRaises(ValueError): validate_config(cfg)
    def test_request_rate_never_exposes_body(self):
        self.b.limits['messages_per_minute']=1; self.send()
        with self.assertRaises(Fault) as e:self.send('second')
        self.assertEqual(e.exception.status,429)

if __name__=='__main__': unittest.main()

class ReviewRegressions(unittest.TestCase):
    def test_recent_interrupted_processing_is_quarantined_on_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path=str(Path(temp)/'state.db')
            b=Bridge(path,[P,Q],Callback([]))
            mid=b.enqueue(P,{'idempotency_key':'restart','operation':'read','body':'Synthetic'})['id']
            b.save_result(Q,{'message_id':mid,'state':'processing'}); b.db.close()
            b=Bridge(path,[P,Q],Callback([]))
            self.assertEqual(b.get_message(Q,mid)['processing_state'],'awaiting_approval')
            b.db.close()
    def test_string_operation_policy_rejected(self):
        cfg={'tunnel_id':'tunnel_synthetic000','principals':[dict(P,allowed_operations='read',expires_at=4102444800,require_subscription=True)],'callback_hosts':['connectors.api.openai.com']}
        with self.assertRaises(ValueError): validate_config(cfg)
    def test_expired_principal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            b=Bridge(str(Path(temp)/'state.db'),[dict(P,expires_at=1)],Callback([]))
            with self.assertRaises(Fault): b.authenticate('Bearer synthetic-only-a')
            b.db.close()
    def test_required_subscription_prevents_undeliverable_acceptance(self):
        with tempfile.TemporaryDirectory() as temp:
            p=dict(P,require_subscription=True)
            b=Bridge(str(Path(temp)/'state.db'),[p,Q],Callback([]))
            with self.assertRaises(Fault): b.enqueue(p,{'idempotency_key':'no-sub','operation':'read','body':'Synthetic'})
            self.assertEqual(b.db.execute('select count(*) from messages').fetchone()[0],0)
            b.db.close()


class SubscriberGuards(unittest.TestCase):
    def test_approval_requires_eligible_subscriber(self):
        with tempfile.TemporaryDirectory() as temp:
            b=Bridge(str(Path(temp)/'state.db'),[P,Q],Callback([]))
            mid=b.enqueue(P,{'idempotency_key':'approval','operation':'change','body':'Synthetic'})['id']
            with self.assertRaises(Fault): b.approve_local(mid)
            self.assertEqual(b.get_message(Q,mid)['processing_state'],'awaiting_approval')
            b.db.close()
    def test_expired_consumer_does_not_count_or_receive(self):
        with tempfile.TemporaryDirectory() as temp:
            b=Bridge(str(Path(temp)/'state.db'),[P,dict(Q,expires_at=1)],Callback([]))
            with b.db:
                b.db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,1)',('sub_synthetic','consumer','agent-a','https://example.invalid/callback','synthetic-only-unused',None,0,time.time()+60))
            self.assertEqual(b.active_subscriptions('agent-a',time.time()),[])
            b.db.close()
    def test_nonfinite_expiry_rejected(self):
        for value in (float('nan'),float('inf')):
            cfg={'tunnel_id':'tunnel_synthetic000','principals':[dict(P,expires_at=value,require_subscription=True)],'callback_hosts':['connectors.api.openai.com']}
            with self.assertRaises(ValueError): validate_config(cfg)

class OperatorRecovery(unittest.TestCase):
    def test_explicit_reviewed_redelivery_creates_new_event_same_message(self):
        import json
        from unittest.mock import patch
        import bridge_admin
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp); (base/'ops').mkdir(); (base/'data').mkdir()
            (base/'ops/bridge.json').write_text(json.dumps({'principals':[P,Q],'callback_hosts':[]}))
            b=Bridge(str(base/'data/bridge.sqlite3'),[P,Q],Callback([]))
            mid=b.enqueue(P,{'idempotency_key':'recover','operation':'read','body':'Synthetic'})['id']
            with b.db:
                b.db.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,1)',('sub_synthetic','consumer','agent-a','https://example.invalid/callback','synthetic-only-unused',None,0,time.time()+60))
                b.emit(mid,'agent-a',time.time())
                b.db.execute("UPDATE outbox SET state='delivered',attempts=1")
            old=b.db.execute('select id from outbox').fetchone()[0]
            b.db.close()
            with patch.object(bridge_admin,'BASE',base),patch('sys.argv',['bridge_admin.py','retry','--id',old,'--redeliver-reviewed']): bridge_admin.main()
            b=Bridge(str(base/'data/bridge.sqlite3'),[P,Q],Callback([]))
            row=b.db.execute('select id,message,state,payload from outbox').fetchone()
            self.assertNotEqual(row['id'],old); self.assertEqual(row['message'],mid); self.assertEqual(row['state'],'pending')
            self.assertEqual(json.loads(row['payload'])['eventId'],row['id'])
            b.db.close()
