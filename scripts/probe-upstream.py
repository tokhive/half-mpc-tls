#!/usr/bin/env python3
"""Bounded, no-credential public TLS 1.3 / KeyUpdate evidence collection.

Uses the real MPC example, captures its actual ClientHello, and runs an ordinary
TLS 1.3 GET baseline. Baseline ClientHello differs; 401/403 do not prove full
request consumption. Never loads API credentials, disables certificate checks,
or issues a model POST. Defaults target public diagnostic/auth-error endpoints.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fingerprint', Path(__file__).with_name('clienthello-fingerprint.py'))
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)


def baseline(host, path):
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve('prime256v1')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    start = time.monotonic()
    try:
        with opener.open('https://'+host+path, timeout=15) as response:
            status = response.status
        return {'http_status': status, 'tls_verified': True, 'ms': (time.monotonic()-start)*1000}
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return {'http_status': status, 'tls_verified': True, 'ms': (time.monotonic()-start)*1000}
    except (OSError, urllib.error.URLError):
        return {'http_status': None, 'tls_verified': False, 'error': 'network_or_tls_failed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='api.openai.com')
    parser.add_argument('--path', default='/v1/models')
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 1 <= args.samples <= 5:
        parser.error('samples must be 1..5')
    if not args.host or not all(c.isascii() and (c.isalnum() or c in '.-') for c in args.host):
        parser.error('host must be a DNS name')
    if not args.path.startswith('/') or len(args.path) > 512 or not all(0x21 <= ord(c) <= 0x7e for c in args.path):
        parser.error('path must be a bounded origin-form GET path')
    binary = ROOT/'rust/target/release/examples/upstream_probe'
    if not binary.is_file():
        parser.error('build with: cargo build --manifest-path rust/Cargo.toml --locked --release -p tokenhive-tls13 --example upstream_probe')
    os.umask(0o077)
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='tokenhive-upstream-probe-', dir='/tmp'))
    root.mkdir(parents=True, exist_ok=True)
    report = {'created_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'host': args.host, 'path': args.path, 'exit_network': 'this runner, not a production Provider',
              'probe_binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'ordinary_tls_baseline': baseline(args.host, args.path), 'samples': [],
              'limitations': ['Ordinary TLS baseline uses a different ClientHello.',
                             'A 401/403 may precede full request consumption.',
                             'No authenticated business call, paid inference, model or usage verification.']}
    for number in range(args.samples):
        capture = root/f'clienthello-{number}.bin'
        try:
            result = subprocess.run([str(binary), args.host, args.path, str(capture)],
                                    capture_output=True, text=True, timeout=65)
            # The binary emits redacted JSON only on stdout; retain no arbitrary body/log.
            row = json.loads(result.stdout.strip()) if result.stdout.strip() else {'error': 'no_probe_summary'}
            row['exit_code'] = result.returncode
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            row = {'error': 'probe_timeout_or_invalid_summary'}
        if capture.is_file():
            row['fingerprint'] = fp.fingerprint(capture.read_bytes())
        report['samples'].append(row)
        (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    fingerprints = [row['fingerprint']['ja4'] for row in report['samples'] if 'fingerprint' in row]
    report['fingerprint_repeated_consistently'] = len(fingerprints) >= 2 and len(set(fingerprints)) == 1
    (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f'Artifacts: {root}', flush=True)
    for row in report['samples']:
        print(json.dumps({k: row.get(k) for k in ('stage', 'error', 'http_status', 'authenticated_close', 'exit_code')}))


if __name__ == '__main__':
    main()
