import base64
import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from bridge import Bridge, Callback, Fault, Server, encode, signature, verify_signature

SECRET = 'whsec_' + base64.b64encode(b'synthetic-test-signing-key-32byte!').decode()
TOKEN = 'synthetic-sender-token'
CONSUMER_TOKEN = 'synthetic-consumer-token'
P = {'id': 'muse', 'role': 'sender', 'token_sha256': hashlib.sha256(TOKEN.encode()).hexdigest()}
Q = {'id': 'dot', 'role': 'consumer', 'senders': ['muse'], 'token_sha256': hashlib.sha256(CONSUMER_TOKEN.encode()).hexdigest()}
OTHER = {'id': 'other', 'role': 'sender', 'token_sha256': hashlib.sha256(b'other-synthetic-token').hexdigest()}

class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        ok = verify_signature(self.server.secret, self.headers['webhook-id'], self.headers['webhook-timestamp'], body, self.headers['webhook-signature'])
        if not ok:
            status, response = 401, {}
        else:
            event = json.loads(body)
            self.server.received.append((event, dict(self.headers)))
            if event.get('type') == 'verification':
                response = {'challenge': 'wrong' if self.server.bad_challenge else event['challenge']}
                status = 200
            else:
                response, status = {}, self.server.status
        raw = encode(response)
        self.send_response(status); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = self.tmp.name + '/state.db'
        self.receiver = HTTPServer(('127.0.0.1', 0), Receiver)
        self.receiver.secret, self.receiver.bad_challenge, self.receiver.status, self.receiver.received = SECRET, False, 200, []
        self.rt = threading.Thread(target=self.receiver.serve_forever); self.rt.start()
        self.url = 'http://127.0.0.1:%s/callback' % self.receiver.server_port
        self.cb = Callback([], test_port=self.receiver.server_port)
        self.bridge = Bridge(self.path, [P, Q, OTHER], self.cb)
        self.server = Server(('127.0.0.1', 0), self.bridge)
        self.st = threading.Thread(target=self.server.serve_forever); self.st.start()
        self.args = {'name': 'message.created', 'arguments': {'sender_id': 'muse'}, 'delivery': {'mode': 'webhook', 'url': self.url, 'secret': SECRET}}
    def tearDown(self):
        self.server.shutdown(); self.st.join(); self.server.server_close()
        self.receiver.shutdown(); self.rt.join(); self.receiver.server_close()
        self.bridge.db.close(); self.tmp.cleanup()
    def request(self, path, body=None, token=TOKEN, overrides=None):
        c = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
        if path == '/mcp' and isinstance(body, dict):
            headers.update({'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': body.get('method', ''), 'Accept': 'application/json, text/event-stream'})
            if body.get('method') == 'tools/call':
                headers['Mcp-Name'] = body['params']['name']
        if overrides:
            headers.update(overrides)
        c.request('GET' if body is None else 'POST', path, None if body is None else encode(body), headers)
        r = c.getresponse(); value = json.loads(r.read()); status = r.status; c.close(); return status, value
    def rpc(self, method, params={}):
        return self.request('/mcp', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': dict(params, _meta={'io.modelcontextprotocol/clientInfo': {'name': 'synthetic-test', 'version': '1'}, 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {}})}, CONSUMER_TOKEN)[1]
    def add(self, idem='one', body='Synthetic task'):
        return self.bridge.enqueue(P, {'idempotency_key': idem, 'body': body})['id']
    def sub(self): return self.bridge.subscribe(Q, self.args)
    def test_http_lifecycle_and_loop_prevention(self):
        self.assertEqual(self.rpc('server/discover')['result']['supportedVersions'], ['2026-07-28'])
        self.assertEqual(self.rpc('events/list')['result']['events'][0]['name'], 'message.created')
        self.assertEqual(len(self.rpc('tools/list')['result']['tools']), 2)
        self.assertIn('id', self.rpc('events/subscribe', self.args)['result'])
        status, result = self.request('/v1/messages', {'idempotency_key': 'http', 'body': 'Synthetic request'})
        self.assertEqual(status, 200); mid = result['id']; self.bridge.tick()
        event, headers = self.receiver.received[-1]
        self.assertEqual(event['data']['message_id'], mid)
        self.assertEqual(headers['webhook-id'], event['eventId'])
        read = self.rpc('tools/call', {'name': 'get_message', 'arguments': {'message_id': mid}})
        self.assertIn('Synthetic request', read['result']['content'][0]['text'])
        args = {'message_id': mid, 'state': 'completed', 'result': 'Synthetic answer'}
        self.rpc('tools/call', {'name': 'save_result', 'arguments': args})
        self.rpc('tools/call', {'name': 'save_result', 'arguments': args})
        self.assertEqual(self.request('/v1/messages/' + mid)[1]['result'], 'Synthetic answer')
        self.assertEqual(self.bridge.db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
        self.assertTrue(self.rpc('tools/call', {'name': 'save_result', 'arguments': dict(args, result='conflicting')})['result']['isError'])
    def test_auth_and_sender_isolation(self):
        self.assertEqual(self.request('/v1/messages', {}, 'bad')[0], 401)
        mid = self.add()
        self.assertEqual(self.request('/v1/messages/' + mid, token='other-synthetic-token')[0], 403)
        self.assertEqual(self.request('/mcp', {'id': 1, 'jsonrpc': '2.0', 'method': 'events/list'})[0], 403)
        with self.assertRaises(Fault): self.bridge.subscribe(dict(Q, senders=[]), self.args)
        with self.assertRaises(Fault): self.bridge.save_result(P, {'message_id': mid, 'state': 'failed'})
    def test_duplicate_conflict_and_filter(self):
        self.sub(); mid = self.add()
        self.assertEqual(self.add(), mid)
        with self.assertRaises(Fault): self.add(body='changed')
        self.bridge.enqueue(OTHER, {'idempotency_key': 'one', 'body': 'Other sender'})
        self.assertEqual(self.bridge.db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
    def test_process_restart_persistence(self):
        self.sub(); mid = self.add()
        self.bridge.save_result(Q, {'message_id': mid, 'state': 'processing'})
        script = "from bridge import Bridge,Callback; import sys; b=Bridge(sys.argv[1],[],Callback([])); assert b.db.execute('select count(*) from subscriptions').fetchone()[0]==1; assert b.db.execute('select count(*) from outbox').fetchone()[0]==1; assert b.db.execute('select state from messages').fetchone()[0]=='awaiting_approval'; b.db.close()"
        subprocess.run([sys.executable, '-c', script, self.path], check=True)
        self.bridge.db.close(); self.bridge = Bridge(self.path, [P,Q,OTHER], self.cb); self.server.bridge = self.bridge
        self.bridge.tick(); self.assertEqual(self.bridge.get_message(Q, mid)['deliveries'][0]['state'], 'cancelled')
    def test_retry_stable_id_and_exhaustion(self):
        self.sub(); self.add(); self.receiver.status = 503
        self.bridge.tick(); first = self.receiver.received[-1][0]['eventId']
        for _ in range(5):
            self.bridge.db.execute('UPDATE outbox SET next=0'); self.bridge.db.commit(); self.bridge.tick()
        row = self.bridge.db.execute('SELECT * FROM outbox').fetchone()
        self.assertEqual((row['state'], row['attempts']), ('dead', 6))
        self.assertEqual(self.receiver.received[-1][0]['eventId'], first)
    def test_retry_then_success(self):
        self.sub(); self.add(); self.receiver.status = 429; self.bridge.tick()
        self.receiver.status = 200
        self.bridge.db.execute('UPDATE outbox SET next=0'); self.bridge.db.commit(); self.bridge.tick()
        self.assertEqual(tuple(self.bridge.db.execute('SELECT state,attempts FROM outbox').fetchone()), ('delivered',2))
    def test_410_and_413_no_retry(self):
        self.sub(); self.add(); self.receiver.status = 413; self.bridge.tick()
        self.assertEqual(self.bridge.db.execute('SELECT state FROM outbox').fetchone()[0], 'dead')
        self.add('two'); self.receiver.status = 410; self.bridge.tick()
        self.assertEqual(self.bridge.db.execute('SELECT active FROM subscriptions').fetchone()[0], 0)
    def test_unsubscribe_idempotent(self):
        self.sub(); self.add()
        args = json.loads(json.dumps(self.args)); del args['delivery']['secret']
        self.assertEqual(self.rpc('events/unsubscribe', args)['result'], {'resultType': 'complete'})
        self.assertEqual(self.rpc('events/unsubscribe', args)['result'], {'resultType': 'complete'})
        self.bridge.tick(); self.assertEqual(len(self.receiver.received), 1)
        self.assertEqual(self.bridge.db.execute('SELECT state FROM outbox').fetchone()[0], 'cancelled')
    def test_refresh_rotation_and_expiry(self):
        sid = self.sub()['id']; self.assertEqual(self.sub()['id'], sid)
        self.assertEqual(len(self.receiver.received), 1)
        replacement = 'whsec_' + base64.b64encode(b'r' * 32).decode()
        self.args['delivery']['secret'] = replacement; self.receiver.secret = replacement
        self.assertEqual(self.sub()['id'], sid)
        self.add(); self.bridge.tick()
        self.assertEqual(len(self.receiver.received[-1][1]['webhook-signature'].split()), 2)
        self.add('expire'); self.bridge.db.execute('UPDATE subscriptions SET expires=0'); self.bridge.db.commit(); self.bridge.tick()
        self.assertEqual(self.bridge.get_message(Q, self.bridge.db.execute("SELECT id FROM messages WHERE idem='expire'").fetchone()[0])['deliveries'][0]['state'], 'cancelled')
    def test_revocation(self):
        self.sub(); self.add(); self.bridge.principals = [P]; self.bridge.tick()
        self.assertEqual(self.bridge.db.execute('SELECT state FROM outbox').fetchone()[0], 'cancelled')
    def test_invalid_signature_challenge_and_secret(self):
        self.receiver.secret = 'whsec_' + base64.b64encode(b'x' * 32).decode()
        result = self.rpc('events/subscribe', self.args)
        self.assertEqual(result['error']['code'], -32015)
        self.receiver.secret = SECRET; self.receiver.bad_challenge = True
        self.assertEqual(self.rpc('events/subscribe', self.args)['error']['data']['reason'], 'challenge_failed')
        self.args['delivery']['secret'] = 'whsec_bad'
        self.assertIn('error', self.rpc('events/subscribe', self.args))
        self.assertEqual(self.bridge.db.execute('SELECT count(*) FROM subscriptions').fetchone()[0], 0)
    def test_signature_tamper_and_stale(self):
        body = b'{}'; now = int(time.time()); sig = signature(SECRET, 'event', now, body)
        self.assertTrue(verify_signature(SECRET, 'event', now, body, sig))
        self.assertFalse(verify_signature(SECRET, 'event', now, b'changed', sig))
        self.assertFalse(verify_signature(SECRET, 'event', now-1000, body, sig))
    def test_ssrf_and_rebinding(self):
        cb = Callback(['callback.example'])
        for url in ['http://callback.example/a','https://127.0.0.1/a','https://callback.example@127.0.0.1/','https://callback.example:444/a','https://callback.example/#x']:
            with self.assertRaises(Fault): cb.target(url)
        with patch('socket.getaddrinfo', return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]):
            with self.assertRaises(Fault): cb.target('https://callback.example/a')
        self.sub(); self.add()
        self.receiver.status = 302; self.bridge.tick()
        self.assertEqual(self.bridge.db.execute('SELECT state FROM outbox').fetchone()[0], 'dead')
    def test_concurrent_duplicate_burst(self):
        self.sub()
        with ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda _: self.add('burst'), range(24)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(self.bridge.db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
        self.assertEqual(self.bridge.db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
    def test_ttl_and_cursor_validation(self):
        self.args['ttlMs'] = 1000
        before = time.time(); self.sub()
        expiry = self.bridge.db.execute('SELECT expires FROM subscriptions').fetchone()[0]
        self.assertLessEqual(expiry, before + 1.1)
        self.args['cursor'] = 'unsupported'
        with self.assertRaises(Fault): self.sub()
    def test_protocol_header_validation(self):
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'server/discover', 'params': {'_meta': {'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientInfo': {}, 'io.modelcontextprotocol/clientCapabilities': {}}}}
        status, result = self.request('/mcp', body, CONSUMER_TOKEN, {'Mcp-Method': 'wrong'})
        self.assertEqual((status, result['error']['code']), (400,-32020))
        body['params']['_meta']['io.modelcontextprotocol/protocolVersion'] = '1900-01-01'
        status, result = self.request('/mcp', body, CONSUMER_TOKEN, {'MCP-Protocol-Version': '1900-01-01'})
        self.assertEqual((status, result['error']['code']), (400,-32022))
        self.assertEqual(result['error']['data']['supported'], ['2026-07-28'])
    def test_expiry_rechecked_between_deliveries_and_backoff(self):
        self.sub(); self.add('slow1'); self.add('slow2')
        self.bridge.db.execute('UPDATE subscriptions SET expires=1005'); self.bridge.db.commit()
        clock = [1000.0]
        def slow(*args):
            clock[0] += 10
            return 503, b'{}'
        with patch('bridge.time.time', side_effect=lambda: clock[0]), patch.object(self.bridge, 'signed_post', side_effect=slow) as send:
            self.bridge.tick()
        rows = self.bridge.db.execute('SELECT state,next FROM outbox ORDER BY rowid').fetchall()
        self.assertEqual(send.call_count, 1)
        self.assertEqual(rows[1]['state'], 'cancelled')
        self.assertGreater(rows[0]['next'], 1010)
    def test_callback_dns_deadline(self):
        cb = Callback(['callback.example'], timeout=0.05)
        def slow(*args, **kwargs):
            time.sleep(0.2)
            return []
        started = time.monotonic()
        with patch('socket.getaddrinfo', side_effect=slow):
            with self.assertRaises(Fault) as ctx:
                cb.target('https://callback.example/')
        self.assertEqual(ctx.exception.reason, 'timeout')
        self.assertLess(time.monotonic() - started, 0.15)
    def test_callback_total_deadline(self):
        cb = Callback([], test_port=self.receiver.server_port, timeout=0.08)
        original = Receiver.do_POST
        def slow(handler):
            time.sleep(0.2)
            try:
                original(handler)
            except (BrokenPipeError, ConnectionResetError):
                pass
        started = time.monotonic()
        with patch.object(Receiver, 'do_POST', slow):
            with self.assertRaises((TimeoutError, OSError)):
                self.bridge.callback = cb
                self.bridge.signed_post({'id':'sub_test','url':self.url,'secret':SECRET}, 'e1', encode({'type':'verification','challenge':'synthetic'}))
            self.assertLess(time.monotonic() - started, 0.18)
            time.sleep(0.2)
    def test_tool_execution_error_result(self):
        result = self.rpc('tools/call', {'name':'get_message', 'arguments':{'message_id':'missing'}})
        self.assertTrue(result['result']['isError'])
        self.assertEqual(result['result']['resultType'], 'complete')
    def test_actual_cli_restart_preserves_message(self):
        config = self.tmp.name + '/synthetic-config.json'
        with open(config, 'w') as f:
            json.dump({'principals':[P,Q], 'callback_hosts':[]}, f)
        os.chmod(config, 0o600)
        probe = socket.socket(); probe.bind(('127.0.0.1',0)); port = probe.getsockname()[1]; probe.close()
        command = [sys.executable, 'bridge.py', '--config', config, '--data', self.tmp.name + '/cli-data', '--port', str(port)]
        def launch():
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # The CLI emits its ready line only after binding; bound test timeout avoids hanging.
            import selectors
            sel = selectors.DefaultSelector(); sel.register(process.stdout, selectors.EVENT_READ)
            ready = sel.select(5); sel.close()
            if not ready:
                process.kill(); process.communicate(); self.fail('CLI startup timeout')
            self.assertIn('loopback', process.stdout.readline())
            return process
        def stop(process):
            process.terminate(); process.communicate(timeout=5)
        process = launch()
        try:
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            c.request('POST','/v1/messages', encode({'idempotency_key':'restart','body':'synthetic persisted message'}), {'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'})
            r = c.getresponse(); self.assertEqual(r.status,200); mid = json.loads(r.read())['id']; c.close()
        finally:
            stop(process)
        process = launch()
        try:
            c = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            c.request('GET','/v1/messages/'+mid,headers={'Authorization':'Bearer '+TOKEN})
            r = c.getresponse(); self.assertEqual(r.status,200); self.assertEqual(json.loads(r.read())['body'],'synthetic persisted message'); c.close()
        finally:
            stop(process)
    def test_no_oauth_metadata_without_auth_bypass(self):
        self.assertEqual(self.request('/.well-known/oauth-protected-resource/mcp', token='')[0],404)
        self.assertEqual(self.request('/', token='')[0],404)
        self.assertEqual(self.request('/mcp', token='')[0],401)
        self.assertEqual(self.request('/v1/messages/missing', token='')[0],401)
    def test_limits_and_malformed(self):
        self.assertEqual(self.request('/v1/messages', {'idempotency_key':'x','body':'x'*70000})[0],413)
        self.assertEqual(self.request('/v1/messages', {'idempotency_key':'x','body':'x','sender_id':'other'})[0],400)
        self.assertEqual(self.request('/v1/messages', [1,2])[0],400)
        self.assertIn('error', self.rpc('unknown'))

if __name__ == '__main__': unittest.main(verbosity=2)
