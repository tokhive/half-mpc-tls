#!/usr/bin/env python3
"""Bounded local stability / crash tests. Generated credentials and synthetic upstream only."""
import argparse
import importlib.util
import http.client
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('benchmark-e2e.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def save(path, value):
    temporary=path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n')
    temporary.replace(path)


class Deployment(bench.Deployment):
    def __init__(self, *args, **kw):
        self.profile = kw.pop('profile', False)
        self.commands = {}
        self.generations = {}
        self.events = []
        super().__init__(*args, **kw)

    def launch(self, name, command):
        if name == 'hub' and self.profile:
            command = [bench.ROOT/'bin/tokenhive-profile-hub', command[1], self.directory/'hub-cpu.pprof']
        self.commands[name] = list(map(str, command))
        generation = self.generations.get(name, 0)
        self.generations[name] = generation + 1
        log = open(self.directory/f'{name}-{generation}.log', 'wb')
        self.logs.append(log)
        p = subprocess.Popen(self.commands[name], cwd=bench.ROOT, stdout=log, stderr=log)
        self.processes.append((name, p))

    def restart(self, name, hard=True):
        p = next(p for n,p in self.processes if n == name)
        started = time.monotonic()
        p.send_signal(signal.SIGKILL if hard else signal.SIGTERM)
        p.wait(timeout=20)
        self.processes = [(n,x) for n,x in self.processes if x is not p]
        # The supervisor explicitly removes only its own dead process's socket.
        # The sidecar correctly refuses to delete an arbitrary existing path.
        socket_name = {'hub-sidecar': 'hub.sock', 'provider-sidecar': 'provider.sock'}.get(name)
        removed = False
        if socket_name and (self.directory/socket_name).exists():
            path = self.directory/socket_name
            if not path.is_socket():
                raise RuntimeError('refusing to remove non-socket')
            path.unlink()
            removed = True
        self.launch(name, self.commands[name])
        self.wait_ready()
        event = {'process':name,'hard':hard,'exit_code':p.returncode,
                 'ready_ms':(time.monotonic()-started)*1000,'supervisor_removed_stale_socket':removed}
        self.events.append(event)
        return event

    def call(self, path, body=None, key=None, timeout=35):
        headers = {'Authorization':'Bearer '+self.token}
        if body is not None:
            headers['Content-Type']='application/json'
        if key:
            headers['Idempotency-Key']=key
        request = urllib.request.Request(self.api_url+path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        return self.opener.open(request, timeout=timeout)

    def task(self,key):
        with self.call('/v1/tasks/by-key/'+key) as r:
            return json.load(r)


def wait_for(condition, seconds=40):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if condition(): return
        time.sleep(.05)
    raise RuntimeError('condition deadline exceeded')


def accounts(d):
    path=d.directory/'state/accounts.jsonl'
    records=[json.loads(l) for l in path.read_text().splitlines()]
    reserve={r['payload']['TaskID'] for r in records if r['kind']=='reserve'}
    settled=[r['payload']['task_id'] for r in records if r['kind']=='settle']
    cancelled=[r['payload']['task_id'] for r in records if r['kind']=='cancel']
    receipt_path=d.directory/'state/receipts.jsonl'
    receipts=[json.loads(l)['receipt']['task_id'] for l in receipt_path.read_text().splitlines()] if receipt_path.exists() else []
    assert len(settled)==len(set(settled)) and len(cancelled)==len(set(cancelled))
    assert not set(settled)&set(cancelled)
    assert set(receipts)==set(settled)
    return {'reserved':len(reserve),'settled':len(settled),'cancelled':len(cancelled),
            'pending':len(reserve-set(settled)-set(cancelled)),'receipts':len(receipts)}


def fault_cases(root, only_hub=False):
    d=Deployment(root,'faults',delay_ms=.01)
    results=[]
    try:
        for name in (['hub'] if only_hub else ['hub','agent','hub-sidecar','provider-sidecar']):
            d.wait_ready()
            key='fault-'+name
            # Stream is deliberately long enough to observe actual response content
            # before terminating a process. This is not an idle restart test.
            d.handler.event_interval = .15
            with d.call('/v1/chat/completions',{'model':'demo-model','messages':[], 'stream':True, 'stream_options':{'include_usage':True}},key) as stream:
                first=stream.readline()
                assert first.startswith(b'data: ') and b'content' in first
                event=d.restart(name)
                try:
                    tail=stream.read()
                    outcome='done' if b'[DONE]' in tail else 'truncated'
                except (OSError, http.client.IncompleteRead) as e:
                    outcome=type(e).__name__
            d.handler.event_interval = .02
            time.sleep(.2)
            status=d.task(key)
            result={'case':name+'-kill-during-sse',**event,'client_outcome':outcome,'task':status}
            results.append(result)
            save(root/'faults.json',results)
            print('FAULT',name,status['state'],event['ready_ms'],flush=True)
            # Record evidence before declaring a failed acceptance condition.
            if status['state']=='pending':
                print('FINDING: orphaned pending reservation after restart',flush=True)
                if only_hub: return
                raise RuntimeError('orphaned reservation after recovery')
            assert status['state']=='cancelled' and status['charge_micros']==0
            assert status['refund_micros']==status['reserved_micros']
            before=d.handler.seen
            try:
                d.call('/v1/chat/completions',{'model':'demo-model','messages':[], 'stream':True, 'stream_options':{'include_usage':True}},key)
                raise AssertionError('same task executed twice')
            except urllib.error.HTTPError as e:
                assert e.code==409
            assert d.handler.seen==before
            recovered=d.load('recovery-'+name, 15, 1, requests=6)
            assert recovered['succeeded']==6 and recovered['failed']==0
        if not only_hub:
            d.wait_ready()
            key='fault-data-partition'
            d.handler.event_interval=.15
            with d.call('/v1/chat/completions',{'model':'demo-model','messages':[], 'stream':True, 'stream_options':{'include_usage':True}},key) as stream:
                assert b'content' in stream.readline()
                started=time.monotonic()
                d.proxy.partition(True)
                time.sleep(3)
                d.proxy.partition(False)
                d.wait_ready()
                recovery_ms=(time.monotonic()-started)*1000
            d.handler.event_interval=.02
            wait_for(lambda:d.task(key)['state']!='pending')
            status=d.task(key)
            assert status['state']=='cancelled' and status['charge_micros']==0
            results.append({'case':'data-partition-3s','ready_ms':recovery_ms,'task':status})
            print('FAULT data-partition',recovery_ms,flush=True)
            recovered=d.load('recovery-data-partition',8,1,requests=3)
            assert recovered['succeeded']==3 and recovered['failed']==0
            d.wait_ready()
            key='downstream-disconnect'
            d.handler.event_interval=.08
            with d.call('/v1/chat/completions',{'model':'demo-model','messages':[], 'stream':True, 'stream_options':{'include_usage':True}},key) as stream:
                assert b'content' in stream.readline()
            wait_for(lambda:d.task(key)['state']!='pending')
            status=d.task(key)
            assert status['state']=='settled' and status['charge_micros']>0
            results.append({'case':'consumer-disconnect-drains-and-settles','task':status})
            # An upstream that keeps streaming beyond the overall request budget
            # must be interrupted even though its transport is still healthy.
            d.wait_ready()
            deadline_key='response-deadline'
            d.handler.event_interval=1
            started=time.monotonic()
            with d.call('/v1/chat/completions',{'model':'demo-model','messages':[], 'stream':True, 'stream_options':{'include_usage':True}},deadline_key) as stream:
                assert b'content' in stream.readline()
                try:
                    tail=stream.read()
                    assert b'[DONE]' not in tail
                except http.client.IncompleteRead:
                    pass
            elapsed=time.monotonic()-started
            assert 24 <= elapsed < 30
            wait_for(lambda:d.task(deadline_key)['state']!='pending')
            deadline_status=d.task(deadline_key)
            assert deadline_status['state']=='cancelled' and deadline_status['charge_micros']==0
            results.append({'case':'response-deadline-25s','elapsed_seconds':elapsed,'task':deadline_status})
            d.handler.event_interval=.02
            event=d.restart('hub',hard=False)
            assert d.task(key)==status
            results.append({'case':'graceful-hub-restart-retains-settlement',**event})
            save(root/'faults.json',results)
        save(root/'accounting.json',accounts(d))
    finally:
        cleanup=d.close() or []
        save(root/'cleanup.json',cleanup)
        print('Artifacts:',root,flush=True)
        if cleanup: raise RuntimeError(f'unclean shutdown: {cleanup}')


def soak(root,seconds):
    d=Deployment(root,'soak')
    rows=[]
    try:
        for name,stream,rate,concurrency in [('json-rate1',False,1,16),('sse-rate1',True,1,16),('saturated-json-c4',False,0,4)]:
            rows.append(d.load(name,seconds,concurrency,stream=stream,rate=rate))
            save(root/'summary.json',rows)
        save(root/'accounting.json',accounts(d))
    finally:
        save(root/'cleanup.json',d.close() or [])
        print('Artifacts:',root,flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['faults','reproduce','soak','profile'],required=True)
    parser.add_argument('--seconds',type=int,default=300,help='each of three continuous soak phases')
    args=parser.parse_args()
    if args.seconds<30 or args.seconds>3600:parser.error('seconds must be 30..3600')
    os.umask(0o077)
    root=Path(tempfile.mkdtemp(prefix='tokenhive-validation-',dir='/tmp'))
    save(root/'metadata.json',{'mode':args.mode,'seconds_per_phase':args.seconds,'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'cpu_count':len(os.sched_getaffinity(0)),
        'binary_sha256':{str(p):hashlib.sha256((bench.ROOT/p).read_bytes()).hexdigest() for p in ('bin/tokenhive-hub','bin/tokenhive-provider-agent','bin/tokenhive-loadtest','rust/target/release/tokenhive-sidecar','bin/tokenhive-profile-hub') if (bench.ROOT/p).exists()}})
    print('Artifacts:',root,flush=True)
    if args.mode=='profile':
        d=Deployment(root,'profile',profile=True)
        try:
            result=d.load('profile-json-c4',60,4)
            save(root/'summary.json',[result])
        finally:
            save(root/'cleanup.json',d.close() or [])
        with open(root/'go-hub-cpu-top.txt','w') as output:
            subprocess.run(['go','tool','pprof','-top',str(d.directory/'hub-cpu.pprof')],cwd=bench.ROOT,stdout=output,check=True)
        with open(root/'go-hub-cpu-cumulative.txt','w') as output:
            subprocess.run(['go','tool','pprof','-top','-cum',str(d.directory/'hub-cpu.pprof')],cwd=bench.ROOT,stdout=output,check=True)
        print('Artifacts:',root,flush=True)
    elif args.mode=='soak':soak(root,args.seconds)
    else:fault_cases(root,args.mode=='reproduce')


if __name__=='__main__':main()
