#!/usr/bin/env python3
"""Real four-process TLS 1.3 load test with public Go SDK and private HTTPS fixture.
Only generated credentials; no external API calls. Results include all failed requests.
"""
import argparse
import asyncio
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request

from demo import ROOT, certificates, free_port, private_json


class Fixture(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    credential = ''
    seen = 0
    event_interval = .02
    lock = threading.Lock()

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path != '/v1/chat/completions' or self.headers.get('Authorization') != 'Bearer '+self.credential:
            self.send_error(403)
            return
        request = json.loads(body)
        if request.get('model') != 'demo-model':
            self.send_error(400)
            return
        with self.lock:
            type(self).seen += 1
            number = type(self).seen
        common = {'id': f'chatcmpl-load-{number}', 'model': 'demo-model', 'created': 0}
        usage = {'prompt_tokens': 128, 'completion_tokens': 40, 'total_tokens': 168}
        streaming = request.get('stream', False)
        if streaming:
            if request.get('stream_options', {}).get('include_usage') is not True:
                self.send_error(400)
                return
            events = [dict(common, object='chat.completion.chunk', choices=[{
                'index': 0, 'delta': {'content': f'{i:02d}'+('x'*62)}, 'finish_reason': None}]) for i in range(40)]
            events += [dict(common, object='chat.completion.chunk', choices=[{
                'index': 0, 'delta': {}, 'finish_reason': 'stop'}]),
                dict(common, object='chat.completion.chunk', choices=[], usage=usage)]
            chunks = [('data: '+json.dumps(e, separators=(',', ':'))+'\n\n').encode() for e in events]
            chunks.append(b'data: [DONE]\n\n')
        else:
            chunks = [json.dumps(dict(common, object='chat.completion', usage=usage, choices=[{
                'index': 0, 'message': {'role': 'assistant', 'content': 'x'*2560}, 'finish_reason': 'stop'}])).encode()]
        # Fixed inference wait before headers/content, followed by timed content events.
        time.sleep(0.2)
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream' if streaming else 'application/json')
        self.send_header('Content-Length', str(sum(map(len, chunks))))
        self.end_headers()
        try:
            for i, chunk in enumerate(chunks):
                self.wfile.write(chunk)
                self.wfile.flush()
                if streaming and i < 39:
                    time.sleep(self.event_interval)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


class TLSServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # MPC handshakes must run in independent handler threads, not the accept loop.
        return self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


class DelayProxy:
    """Bounded pipelined byte-stream delay. Not packet-level WAN emulation."""
    def __init__(self, target, delay_ms):
        self.target = target
        self.blocked = False
        self.writers = set()
        self.delay = delay_ms/1000
        self.port = free_port()
        self.started = threading.Event()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        if not self.started.wait(5):
            raise RuntimeError('delay proxy failed to start')

    async def direction(self, reader, writer):
        queue = asyncio.Queue(maxsize=64)
        async def receive():
            while True:
                data = await reader.read(65536)
                await queue.put((self.loop.time()+self.delay, data))
                if not data:
                    return
        async def send():
            while True:
                due, data = await queue.get()
                await asyncio.sleep(max(0, due-self.loop.time()))
                if not data:
                    return
                writer.write(data)
                await writer.drain()
        tasks = [asyncio.create_task(receive()), asyncio.create_task(send())]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def handle(self, reader, writer):
        other = None
        tasks = []
        self.writers.add(writer)
        try:
            if self.blocked:
                return
            remote, other = await asyncio.open_connection('127.0.0.1', self.target)
            self.writers.add(other)
            if self.blocked:
                return
            tasks = [asyncio.create_task(self.direction(reader, other)),
                     asyncio.create_task(self.direction(remote, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            writer.close()
            self.writers.discard(writer)
            if other:
                other.close()
                self.writers.discard(other)

    def partition(self, blocked):
        """Close existing test data connections and refuse new ones until healed."""
        done = threading.Event()
        def apply():
            self.blocked = blocked
            if blocked:
                for writer in list(self.writers):
                    writer.close()
            done.set()
        self.loop.call_soon_threadsafe(apply)
        if not done.wait(5):
            raise RuntimeError('proxy did not apply partition')

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.server = self.loop.run_until_complete(asyncio.start_server(self.handle, '127.0.0.1', self.port))
        self.started.set()
        self.loop.run_forever()
        tasks = asyncio.all_tasks(self.loop)
        for task in tasks:
            task.cancel()
        self.loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
        self.server.close()
        self.loop.run_until_complete(self.server.wait_closed())
        self.loop.close()

    def close(self):
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


def proc_stats(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()
        return {'cpu_seconds': (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'),
                'rss_mib': int(fields[21])*os.sysconf('SC_PAGE_SIZE')/(1 << 20),
                'threads': int(fields[17]), 'fds': len(list(Path(f'/proc/{pid}/fd').iterdir()))}
    except (OSError, ValueError, IndexError):
        return {'cpu_seconds': 0, 'rss_mib': 0}


def available_mib():
    fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return int(fields['MemAvailable'].split()[0])/1024


class Deployment:
    def __init__(self, parent, name, capacity='baseline', delay_ms=0, max_waiters=64, queue_wait_timeout_ms=10000):
        self.directory = Path(tempfile.mkdtemp(prefix=name+'-', dir=parent))
        self.capacity = capacity
        self.delay_ms = delay_ms
        self.max_waiters = max_waiters
        self.queue_wait_timeout_ms = queue_wait_timeout_ms
        self.processes = []
        self.logs = []
        self.proxy = None
        self.upstream = None
        self.closed = False
        try:
            self.start()
        except BaseException:
            self.close()
            raise

    def start(self):
        d = self.directory
        certificates(d)
        api, control, data = free_port(), free_port(), free_port()
        self.credential = 'load-'+secrets.token_hex(24)
        self.token = 'th_'+secrets.token_hex(24)
        # Each deployment has an independent handler class and request counter.
        self.handler = type('DeploymentFixture', (Fixture,), {'credential': self.credential, 'seen': 0, 'lock': threading.Lock()})
        self.upstream = TLSServer(('127.0.0.1', 0), self.handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = tls.maximum_version = ssl.TLSVersion.TLSv1_3
        tls.set_ecdh_curve('prime256v1')
        tls.load_cert_chain(d/'server.pem', d/'server.key')
        self.upstream.tls = tls
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        upstream_port = self.upstream.server_address[1]
        private_json(d/'credentials.json', {'version': 1, 'credentials': {'demo': self.credential}})
        cfg = json.loads((ROOT/'config/hub.example.json').read_text())
        cfg.update(api_address=f'127.0.0.1:{api}', control_address=f'127.0.0.1:{control}',
                   data_address=f'127.0.0.1:{data}', trust_domain='demo.local', certificate_file=str(d/'server.pem'),
                   private_key_file=str(d/'server.key'), provider_ca_file=str(d/'ca.pem'),
                   hub_sidecar_socket=str(d/'hub.sock'), state_directory=str(d/'state'),
                   api_keys={self.token: 'consumer-1'}, target_ready=2, max_ready=4, max_leased=16,
                   warm_concurrency=2, global_warm_concurrency=2, request_timeout_seconds=25,
                   max_waiters=self.max_waiters, queue_wait_timeout_ms=self.queue_wait_timeout_ms,
                   api_limits={'requests_per_second': 100, 'burst': 100, 'max_concurrent': 32})
        capacities = {p['name']: p['capacity'] for p in json.loads((ROOT/'testdata/mpc-capacities.json').read_text())}
        cfg['routes'][0].update(credential_id='demo', credential_length=len(self.credential), host='localhost',
                               server_name='localhost', port=upstream_port, models=['demo-model'],
                               allowed_response_models=['demo-model'], tls_version='1.3', capacity=capacities[self.capacity])
        cfg['fundings'][0]['amount_micros'] = 100000000
        private_json(d/'hub.json', cfg)
        provider_data = data
        if self.delay_ms:
            self.proxy = DelayProxy(data, self.delay_ms)
            provider_data = self.proxy.port
        cfg = json.loads((ROOT/'config/provider.example.json').read_text())
        cfg.update(control_address=f'127.0.0.1:{control}', data_address=f'127.0.0.1:{provider_data}',
                   hub_server_name='localhost', ca_file=str(d/'ca.pem'), certificate_file=str(d/'provider.pem'),
                   private_key_file=str(d/'provider.key'), sidecar_socket=str(d/'provider.sock'),
                   allowed_hosts=['localhost'], allowed_ports=[upstream_port], drain_file=str(d/'drain'),
                   data_tunnels=16, heartbeat_seconds=1)
        private_json(d/'provider.json', cfg)
        self.api_url = f'https://localhost:{api}'
        private_json(d/'client.json', {'base_url': self.api_url+'/v1', 'api_key': self.token, 'ca_file': str(d/'ca.pem')})
        private_json(d/'direct.json', {'base_url': f'https://localhost:{upstream_port}/v1', 'api_key': self.credential, 'ca_file': str(d/'ca.pem')})
        sidecar = ROOT/'rust/target/release/tokenhive-sidecar'
        flags = ['--tls-version', '1.3', '--capacity', self.capacity, '--upstream-ca', d/'ca.pem']
        self.launch('hub-sidecar', [sidecar, '--role', 'hub', '--socket', d/'hub.sock', *flags])
        self.launch('provider-sidecar', [sidecar, '--role', 'provider', '--socket', d/'provider.sock', *flags,
                                         '--credential-file', d/'credentials.json'])
        started = time.monotonic()
        self.launch('hub', [ROOT/'bin/tokenhive-hub', d/'hub.json'])
        self.launch('agent', [ROOT/'bin/tokenhive-provider-agent', d/'provider.json'])
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(d/'ca.pem'))))
        self.wait_ready()
        self.startup_ready_ms = (time.monotonic()-started)*1000
        print(f'READY {self.capacity} delay={self.delay_ms}ms startup={self.startup_ready_ms:.0f}ms', flush=True)

    def launch(self, name, command):
        log = open(self.directory/(name+'.log'), 'wb')
        self.logs.append(log)
        process = subprocess.Popen(list(map(str, command)), cwd=ROOT, stdout=log, stderr=log)
        self.processes.append((name, process))

    def healthy(self):
        for name, p in self.processes:
            if p.poll() is not None:
                raise RuntimeError(f'{name} exited {p.returncode}; see {self.directory}')
        if available_mib() < 400:
            raise RuntimeError('stopping benchmark: host available memory below 400 MiB')

    def wait_ready(self):
        deadline = time.monotonic()+120
        while time.monotonic() < deadline:
            self.healthy()
            try:
                request = urllib.request.Request(self.api_url+'/readyz', headers={'Authorization': 'Bearer '+self.token})
                with self.opener.open(request, timeout=2) as response:
                    if response.status == 200:
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError(f'ready timeout; see {self.directory}')

    def count_receipts(self):
        path = self.directory/'state/receipts.jsonl'
        return sum(1 for _ in path.open()) if path.exists() else 0

    def load(self, name, seconds, concurrency, prompt=1024, stream=False, rate=0, direct=False, ready_each=False, requests=0):
        self.wait_ready()
        output = self.directory/(name+'.json')
        command = [ROOT/'bin/tokenhive-loadtest', '-config', self.directory/('direct.json' if direct else 'client.json'),
                   '-output', output, '-duration', f'{seconds}s', '-concurrency', str(concurrency),
                   '-prompt-bytes', str(prompt), '-rate', str(rate), '-requests', str(requests)]
        if stream:
            command.append('-stream')
        if ready_each:
            command.append('-ready-each')
        before_seen, before_receipts = self.handler.seen, self.count_receipts()
        initial = {name: proc_stats(p.pid) for name, p in self.processes}
        peak = {name: 0 for name, _ in self.processes}
        total_peak = 0
        telemetry = []
        start = time.monotonic()
        print(f'RUN {name}: {seconds}s c={concurrency} rate={rate} prompt={prompt} stream={stream}', flush=True)
        with open(self.directory/(name+'.log'), 'wb') as log:
            process = subprocess.Popen(list(map(str, command)), cwd=ROOT, stdout=log, stderr=log)
            try:
                while process.poll() is None:
                    self.healthy()
                    row = {n: proc_stats(p.pid) for n, p in self.processes}
                    for n, stats in row.items():
                        peak[n] = max(peak[n], stats['rss_mib'])
                    total_peak = max(total_peak, sum(stats['rss_mib'] for stats in row.values()))
                    telemetry.append({'seconds': time.monotonic()-start, 'processes': row,
                                      'loadgen': proc_stats(process.pid), 'fixture_and_harness': proc_stats(os.getpid()),
                                      'host_available_mib': available_mib()})
                    if time.monotonic()-start > seconds+40:
                        raise RuntimeError('load generator exceeded bounded run time')
                    time.sleep(0.25)
                if process.returncode != 0:
                    raise RuntimeError(f'load generator exited {process.returncode}; see {name}.log')
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        elapsed = time.monotonic()-start
        final = {n: proc_stats(p.pid) for n, p in self.processes}
        result = json.loads(output.read_text())
        result.update(name=name, capacity=self.capacity, one_way_data_delay_ms=self.delay_ms,
                      direct=direct, startup_ready_ms=self.startup_ready_ms,
                      process_cpu_seconds={n: final[n]['cpu_seconds']-initial[n]['cpu_seconds'] for n in initial},
                      process_peak_rss_mib=peak, sum_peak_rss_mib=total_peak,
                      resource_window_seconds=elapsed, upstream_requests=self.handler.seen-before_seen,
                      durable_receipts=self.count_receipts()-before_receipts)
        result['mean_cpu_cores'] = sum(result['process_cpu_seconds'].values())/elapsed
        # Exclude startup inventory and the post-admission drain from this rate.
        measured_window = min(seconds, result['elapsed_seconds'])
        trim = min(10, measured_window/3)
        steady = [r for r in result['samples'] if not r.get('error') and
                  trim*1000 <= r['start_ms']+r['total_ms'] <= measured_window*1000]
        result['steady_completion_rps'] = len(steady)/(measured_window-trim)
        result['steady_window_seconds'] = measured_window-trim
        result['admission_error_ratio'] = (result['failed']+result['dropped_arrivals'])/max(1, result['attempted']+result['dropped_arrivals'])
        # Every successful gateway response must have a committed receipt. A failed
        # client request may nevertheless have reached upstream: retain that evidence.
        if not direct and result['durable_receipts'] < result['succeeded']:
            raise RuntimeError('successful responses lack durable receipts')
        if not direct and result['failed'] == 0 and (result['upstream_requests'] != result['succeeded'] or result['durable_receipts'] != result['succeeded']):
            raise RuntimeError('upstream/receipt counts differ from successful requests')
        private_json(self.directory/(name+'-resources.json'), telemetry)
        output.write_text(json.dumps(result, indent=2)+'\n')
        summary = {k: v for k, v in result.items() if k != 'samples'}
        print(f"RESULT {name}: ok={result['succeeded']} fail={result['failed']} dropped={result['dropped_arrivals']} rps={result['completed_rps']:.2f} first={result['first_content_ms']} RSS={total_peak:.0f}MiB CPU={result['mean_cpu_cores']:.2f}", flush=True)
        return summary

    def close(self):
        if self.closed:
            return
        self.closed = True
        failures = []
        for name, p in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
            if p.returncode != 0:
                failures.append((name, p.returncode))
        if self.proxy:
            self.proxy.close()
        if self.upstream:
            self.upstream.shutdown()
            self.upstream.server_close()
        for log in self.logs:
            log.close()
        for filename in ('hub.sock', 'provider.sock'):
            if (self.directory/filename).exists():
                failures.append((filename, 'not removed'))
        if failures:
            print(f'CLEANUP {failures}', flush=True)
        return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=45)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--quick', action='store_true', help='short harness verification, not a performance result')
    parser.add_argument('--max-waiters', type=int, default=64)
    parser.add_argument('--queue-wait-timeout-ms', type=int, default=10000)
    parser.add_argument('--only', help='comma-separated scenario names for a focused rerun')
    args = parser.parse_args()
    selected = set(args.only.split(',')) if args.only else None
    if not 5 <= args.seconds <= 300:
        parser.error('seconds must be 5..300')
    if args.max_waiters <= 0 or args.queue_wait_timeout_ms <= 0:
        parser.error('queue limits must be positive')
    os.umask(0o077)
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='tokenhive-perf-', dir='/tmp'))
    root.mkdir(parents=True, exist_ok=True)
    for binary in ('bin/tokenhive-hub', 'bin/tokenhive-provider-agent', 'bin/tokenhive-loadtest', 'rust/target/release/tokenhive-sidecar'):
        if not (ROOT/binary).exists():
            parser.error(f'missing {binary}; build first')
    meta = {'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'cpu_count': len(os.sched_getaffinity(0)),
            'cpu_model': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
            'mem_total_kib': int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))),
            'platform': platform.platform(), 'python': platform.python_version(), 'seconds': args.seconds,
            'fixture': {'first_response_delay_ms': 200, 'content_events': 40, 'event_interval_ms': 20, 'json_content_bytes': 2560},
            'config': {'target_ready': 2, 'max_ready': 4, 'warm_concurrency': 2, 'global_warm_concurrency': 2, 'data_tunnels': 16,
                       'max_waiters': args.max_waiters, 'queue_wait_timeout_ms': args.queue_wait_timeout_ms},
            'binary_sha256': {p: hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
                 ('bin/tokenhive-hub', 'bin/tokenhive-provider-agent', 'rust/target/release/tokenhive-sidecar')}}
    private_json(root/'metadata.json', meta)
    results = []
    cleanup = []
    d = None
    def record(*a, **kw):
        if selected is not None and a[0] not in selected:
            return
        results.append(d.load(*a, **kw))
        (root/'summary.json').write_text(json.dumps(results, indent=2)+'\n')
    try:
        d = Deployment(root, 'baseline', max_waiters=args.max_waiters, queue_wait_timeout_ms=args.queue_wait_timeout_ms)
        duration = 5 if args.quick else args.seconds
        record('direct-json-c1', duration, 1, direct=True)
        record('direct-sse-c4', duration, 4, stream=True, direct=True)
        record('ready-json-c1', 120 if not args.quick else 15, 1, ready_each=True, requests=100 if not args.quick else 3)
        record('json-c1', duration, 1)
        record('json-c4', duration, 4)
        if not args.quick:
            record('json-c8', duration, 8)
            record('json-rate1', max(duration, 60), 16, rate=1)
            record('json-rate4', max(duration, 60), 16, rate=4)
        record('sse-c4', duration, 4, stream=True)
        cleanup += d.close() or []
        d = None
        if not args.quick:
            for capacity, prompt in [('1m', (1 << 20)-1024), ('5m', (5 << 20)-1024)]:
                d = Deployment(root, capacity, capacity, max_waiters=args.max_waiters, queue_wait_timeout_ms=args.queue_wait_timeout_ms)
                record(capacity+'-json-c2', duration, 2, prompt=prompt)
                record(capacity+'-sse-c2', duration, 2, prompt=prompt, stream=True)
                cleanup += d.close() or []
                d = None
            d = Deployment(root, 'delay5', delay_ms=5, max_waiters=args.max_waiters, queue_wait_timeout_ms=args.queue_wait_timeout_ms)
            record('delay5-json-c4', duration, 4)
            record('delay5-sse-c4', duration, 4, stream=True)
    finally:
        if d:
            cleanup += d.close() or []
        (root/'cleanup.json').write_text(json.dumps(cleanup)+'\n')
        print(f'Artifacts: {root}', flush=True)
    if cleanup:
        raise RuntimeError('unclean process shutdown')
    if selected is not None and selected != {r['name'] for r in results}:
        raise ValueError('unknown or excluded scenario in --only')


if __name__ == '__main__':
    main()
