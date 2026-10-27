#!/usr/bin/env python3
"""Profile real four-process warm-up using generated credentials and a local fixture.

Stage wall/whole-process CPU deltas may overlap. Native macOS samples include
waiting threads; Linux perf may require host permissions. Neither is silently
reported as successful when unavailable. Artifacts can contain generated demo
credentials and remain in a private temporary directory; share summary.json only.
"""
import argparse
from collections import defaultdict
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('bench', Path(__file__).with_name('benchmark-e2e.py'))
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def stages(directory):
    groups = defaultdict(list)
    for path in directory.glob('*sidecar*.log'):
        for line in path.read_text(errors='replace').splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get('type') == 'tokenhive_phase' and row.get('event') == 'end' and row.get('completed'):
                groups[(row['role'], row['phase'])].append(row)
    return [{'role': role, 'phase': phase, 'count': len(rows),
             'wall_ms_median': statistics.median(row['elapsed_ns']/1e6 for row in rows),
             'process_cpu_ms_median': statistics.median(row['process_cpu_ns']/1e6 for row in rows if row.get('process_cpu_ns') is not None)
                if any(row.get('process_cpu_ns') is not None for row in rows) else None}
            for (role, phase), rows in sorted(groups.items())]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--tls-version', choices=('1.2', '1.3'), default='1.3')
    parser.add_argument('--capacity', choices=('baseline', '16k', '64k', '256k', '1m', '5m'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 300:
        parser.error('seconds must be 10..300')
    os.umask(0o077)
    os.environ['TOKENHIVE_PROFILE_STAGES'] = '1'
    root = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='tokenhive-warm-profile-', dir='/tmp'))
    root.mkdir(parents=True, exist_ok=True)
    capacity = args.capacity or ('5m' if args.tls_version == '1.3' else 'baseline')
    native = []
    samplers = []
    deployment = None
    report = {'host': bench.host_metadata(), 'tls_version': args.tls_version, 'capacity': capacity,
              'binary_sha256': {name: hashlib.sha256((bench.ROOT/name).read_bytes()).hexdigest() for name in
                                ('bin/tokenhive-hub', 'bin/tokenhive-provider-agent', 'rust/target/release/tokenhive-sidecar')},
              'limitations': ['Whole-process CPU deltas include concurrent tasks; nested intervals cannot be added.',
                             'Native stack samples on macOS include idle/waiting threads.',
                             'Generated local upstream; no production-model or WAN capacity claim.']}
    try:
        deployment = bench.Deployment(root, 'profile', capacity=capacity, tls_version=args.tls_version)
        for name, process in deployment.processes:
            if 'sidecar' not in name:
                continue
            output = root/(name+('.sample.txt' if platform.system() == 'Darwin' else '.perf.data'))
            if platform.system() == 'Darwin':
                command = ['sample', str(process.pid), str(args.seconds), '10', '-file', str(output)]
            elif shutil.which('perf'):
                command = ['perf', 'record', '-F', '99', '-g', '-p', str(process.pid), '-o', str(output), '--', 'sleep', str(args.seconds)]
            else:
                native.append({'process': name, 'status': 'unavailable', 'reason': 'perf not installed'})
                continue
            log = open(root/(name+'-sampler.log'), 'wb')
            sampler = subprocess.Popen(command, stdout=log, stderr=log)
            samplers.append((name, sampler, log, output))
        report['load'] = deployment.load('warm-profile', args.seconds, 4)
    finally:
        for name, sampler, log, output in samplers:
            try:
                code = sampler.wait(timeout=args.seconds+10)
            except subprocess.TimeoutExpired:
                sampler.kill()
                code = sampler.wait()
            log.close()
            native.append({'process': name, 'status': 'captured' if code == 0 and output.exists() else 'failed', 'exit_code': code, 'artifact': output.name})
        if deployment:
            report['cleanup'] = deployment.close()
            report['stages'] = stages(deployment.directory)
        report['native_sampling'] = native
        (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        print(f'Artifacts: {root}', flush=True)
    if not report.get('stages'):
        raise RuntimeError('no stage timings captured; rebuild the sidecar with current sources')
    if report.get('cleanup') or report['load']['failed']:
        raise RuntimeError('profiling workload or cleanup failed; inspect retained artifacts')


if __name__ == '__main__':
    main()
