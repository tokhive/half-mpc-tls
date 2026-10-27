#!/usr/bin/env python3
"""Start a private local deployment with real MPC and a deterministic TLS upstream.
No real API credentials or paid upstream calls. Requires built binaries and openssl.
Use --check for automated acceptance, otherwise keep serving until Ctrl-C.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def private_json(path, value):
    with open(path, 'x', encoding='utf-8') as f:
        os.chmod(path, 0o600)
        json.dump(value, f, indent=2)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def certificates(directory):
    def run(*args):
        subprocess.run(['openssl', *args], cwd=directory, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
        '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=TokenHive local demo CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    for name, usage, san in [('server', 'serverAuth', 'DNS:localhost'),
                             ('provider', 'clientAuth', 'URI:spiffe://demo.local/provider/provider-1')]:
        run('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name+'.key',
            '-out', name+'.csr', '-subj', '/CN='+name)
        (directory / (name+'.ext')).write_text(
            'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
            f'extendedKeyUsage={usage}\nsubjectAltName={san}\n')
        run('x509', '-req', '-in', name+'.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
            '-CAcreateserial', '-days', '2', '-sha256', '-out', name+'.pem',
            '-extfile', name+'.ext')
    for path in directory.iterdir():
        path.chmod(0o600)


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    credential = ''
    requests_seen = 0
    lock = threading.Lock()

    def log_message(self, *_):
        pass  # Never log credentials or business payloads.

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path != '/v1/chat/completions' or self.headers.get('Authorization') != 'Bearer '+self.credential:
            self.send_error(403)
            return
        request = json.loads(body)
        with self.lock:
            type(self).requests_seen += 1
        common = {'id': 'chatcmpl-demo', 'model': 'demo-model', 'created': 0}
        usage = {'prompt_tokens': 8, 'completion_tokens': 2, 'total_tokens': 10}
        streaming = request.get('stream', False)
        if streaming:
            if request.get('stream_options', {}).get('include_usage') is not True:
                self.send_error(400)
                return
            events = [dict(common, object='chat.completion.chunk', choices=[{
                'index': 0, 'delta': {'role':'assistant', 'content':'Hello from real MPC'}, 'finish_reason':None}]),
                dict(common, object='chat.completion.chunk', choices=[{
                    'index':0, 'delta':{}, 'finish_reason':'stop'}]),
                dict(common, object='chat.completion.chunk', choices=[], usage=usage)]
            chunks = [('data: '+json.dumps(e)+'\n\n').encode() for e in events] + [b'data: [DONE]\n\n']
        else:
            chunks = [json.dumps(dict(common, object='chat.completion', usage=usage, choices=[{
                'index':0, 'message':{'role':'assistant','content':'Hello from real MPC'},
                'finish_reason':'stop'}])).encode()]
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream' if streaming else 'application/json')
        self.send_header('Content-Length', str(sum(map(len, chunks))))
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(chunk)
            self.wfile.flush()
            if streaming:
                time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--tls-version', choices=('1.2', '1.3'), default='1.2')
    parser.add_argument('--capacity', choices=('baseline', '16k', '64k', '256k', '1m', '5m'), default='baseline')
    parser.add_argument('--prompt-bytes', type=int, default=5)
    args = parser.parse_args()
    capacities = {p['name']: p['capacity'] for p in json.loads((ROOT/'testdata/mpc-capacities.json').read_text())}
    if not 1 <= args.prompt_bytes <= capacities[args.capacity]['max_request_bytes'] - 1024:
        parser.error('prompt must be positive and leave at least 1024 bytes for headers and JSON')
    hub = ROOT / 'bin/tokenhive-hub'
    agent = ROOT / 'bin/tokenhive-provider-agent'
    sidecar = ROOT / 'rust/target/release/tokenhive-sidecar'
    for binary in (hub, agent, sidecar):
        if not binary.is_file():
            parser.error(f'{binary} missing; run make build first')
    old_umask = os.umask(0o077)
    processes = []
    logs = []
    upstream = None
    failed_shutdown = []
    directory = Path(tempfile.mkdtemp(prefix='tokenhive-demo-', dir='/tmp'))
    # Files are retained for receipt inspection. They contain only generated demo secrets.
    try:
        certificates(directory)
        api_port, control_port, data_port = free_port(), free_port(), free_port()
        credential = 'demo-'+secrets.token_hex(24)
        token = 'th_'+secrets.token_hex(24)
        foreign_token = 'th_'+secrets.token_hex(24)
        Upstream.credential = credential
        upstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = tls.maximum_version = (ssl.TLSVersion.TLSv1_3 if args.tls_version == '1.3' else ssl.TLSVersion.TLSv1_2)
        tls.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
        tls.set_ecdh_curve('prime256v1')
        tls.load_cert_chain(directory/'server.pem', directory/'server.key')
        upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        upstream_port = upstream.server_address[1]
        private_json(directory/'credentials.json', {'version':1,'credentials':{'demo':credential}})
        cfg = json.loads((ROOT/'config/hub.example.json').read_text())
        cfg.update(api_address=f'127.0.0.1:{api_port}', control_address=f'127.0.0.1:{control_port}',
                   data_address=f'127.0.0.1:{data_port}',trust_domain='demo.local',
                   certificate_file=str(directory/'server.pem'),private_key_file=str(directory/'server.key'),
                   provider_ca_file=str(directory/'ca.pem'), hub_sidecar_socket=str(directory/'hub.sock'),
                   state_directory=str(directory/'state'),api_keys={token:'consumer-1',foreign_token:'consumer-2'},max_ready=1,
                   max_leased=1,global_warm_concurrency=1)
        route = cfg['routes'][0]
        route.update(credential_id='demo',credential_length=len(credential),host='localhost',
                     port=upstream_port,server_name='localhost',models=['demo-model'],
                     allowed_response_models=['demo-model'],tls_version=args.tls_version,capacity=capacities[args.capacity])
        private_json(directory/'hub.json',cfg)
        cfg = json.loads((ROOT/'config/provider.example.json').read_text())
        cfg.update(control_address=f'127.0.0.1:{control_port}',data_address=f'127.0.0.1:{data_port}',
                   hub_server_name='localhost',ca_file=str(directory/'ca.pem'),
                   certificate_file=str(directory/'provider.pem'),private_key_file=str(directory/'provider.key'),
                   sidecar_socket=str(directory/'provider.sock'),allowed_hosts=['localhost'],
                   allowed_ports=[upstream_port],drain_file=str(directory/'drain'),data_tunnels=4,
                   heartbeat_seconds=1)
        private_json(directory/'provider.json',cfg)
        private_json(directory/'client.json',{'base_url':f'https://localhost:{api_port}/v1',
                                              'api_key':token,'ca_file':str(directory/'ca.pem'),'model':'demo-model'})
        def start(name, command):
            log = open(directory/(name+'.log'), 'wb')
            logs.append(log)
            p = subprocess.Popen(list(map(str, command)), stdout=log, stderr=log)
            processes.append((name,p))
        sidecar_flags = ['--tls-version', args.tls_version, '--capacity', args.capacity]
        start('hub-sidecar',[sidecar,*sidecar_flags,'--role','hub','--socket',directory/'hub.sock','--upstream-ca',directory/'ca.pem'])
        start('provider-sidecar',[sidecar,*sidecar_flags,'--role','provider','--socket',directory/'provider.sock',
                                 '--credential-file',directory/'credentials.json','--upstream-ca',directory/'ca.pem'])
        start('hub',[hub,directory/'hub.json'])
        start('agent',[agent,directory/'provider.json'])
        context = ssl.create_default_context(cafile=str(directory/'ca.pem'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        def call(path, body=None, key=None, auth=True, api_key=None):
            headers = {'Authorization':'Bearer '+(api_key or token)} if auth else {}
            if body is not None: headers['Content-Type'] = 'application/json'
            if key: headers['Idempotency-Key'] = key
            request = urllib.request.Request(f'https://localhost:{api_port}'+path,
                data=None if body is None else json.dumps(body).encode(), headers=headers)
            try:
                with opener.open(request, timeout=90) as response:
                    return response.status,response.headers,response.read()
            except urllib.error.HTTPError as error:
                with error:
                    return error.code,error.headers,error.read()
        def ready():
            deadline = time.monotonic()+180
            while time.monotonic() < deadline:
                for name,p in processes:
                    if p.poll() is not None: raise RuntimeError(f'{name} exited; inspect {directory}')
                try:
                    if call('/readyz')[0] == 200: return
                except (OSError, urllib.error.URLError): pass
                time.sleep(0.2)
            raise RuntimeError(f'warming timed out; inspect {directory}')
        ready()
        assert call('/healthz',auth=False)[0] == 200
        assert call('/v1/models',auth=False)[0] == 401
        assert json.loads(call('/v1/models')[2])['data'][0]['id'] == 'demo-model'
        body = {'model':'demo-model','messages':[{'role':'user','content':'x'*args.prompt_bytes}]}
        status,headers,result = call('/v1/chat/completions',body,'demo-json')
        assert status == 200, (status,result)
        assert json.loads(result)['usage']['total_tokens'] == 10
        assert headers['X-Request-Id'] == headers['X-TokenHive-Task-Id']
        task_id = headers['X-TokenHive-Task-Id']
        assert json.loads(call('/v1/tasks/'+task_id)[2])['state'] == 'settled'
        assert json.loads(call('/v1/tasks/by-key/demo-json')[2])['task_id'] == task_id
        assert call('/v1/tasks/'+task_id,api_key=foreign_token)[0] == 404
        assert call('/v1/tasks/by-key/demo-json',api_key=foreign_token)[0] == 404
        ready()
        assert call('/v1/chat/completions',body,'demo-json')[0] == 409
        body['stream'] = True  # Deliberately omit stream_options; the gateway supplies it.
        status,headers,result = call('/v1/chat/completions',body,'demo-sse')
        assert status == 200 and result.endswith(b'data: [DONE]\n\n'), (status,result)
        assert b'Hello from real MPC' in result
        assert Upstream.requests_seen == 2, Upstream.requests_seen
        # Both responses are only returned after their receipts have reached the outbox.
        receipts = (directory/'state/receipts.jsonl').read_text().splitlines()
        assert len(receipts) == 2, receipts
        assert (directory/'state/accounts.jsonl').stat().st_size > 0
        # Exercise the public Go SDK against the same real processes.
        subprocess.run(['go','run','./examples/go/chat',str(directory/'client.json')],
                       cwd=ROOT, check=True, timeout=180)
        assert Upstream.requests_seen == 4, Upstream.requests_seen
        assert len((directory/'state/receipts.jsonl').read_text().splitlines()) == 4
        print(f'PASS: real MPC TLS {args.tls_version}, capacity {args.capacity}, prompt {args.prompt_bytes} bytes, JSON, SSE, Go SDK, discovery, authentication, idempotency, durable receipts',flush=True)
        print(f'Client configuration: {directory}/client.json',flush=True)
        print(f'Artifacts and process logs: {directory}',flush=True)
        if not args.check:
            print('Service ready. Ctrl-C stops all processes. Read docs/business-integration-zh.md.',flush=True)
            while True:
                time.sleep(1)
                for name,p in processes:
                    if p.poll() is not None: raise RuntimeError(f'{name} exited')
    finally:
        # Stop agents/Hub before sidecars. Bounded teardown cannot strand a process.
        for name,p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
            if args.check and p.returncode != 0:
                failed_shutdown.append((name,p.returncode))
        if upstream:
            upstream.shutdown(); upstream.server_close()
        for log in logs: log.close()
        os.umask(old_umask)
        if args.check:
            for name in ('hub.sock','provider.sock'):
                if (directory/name).exists():
                    failed_shutdown.append((name,'socket not cleaned up'))
            if failed_shutdown:
                raise RuntimeError(f'Process cleanup failed: {failed_shutdown}; see {directory}')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
