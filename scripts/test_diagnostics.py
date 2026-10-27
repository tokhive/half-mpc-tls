import importlib.util
from pathlib import Path
import unittest
import json
import subprocess
import sys
import tempfile

from host_resources import cpu_seconds

spec = importlib.util.spec_from_file_location('fingerprint', Path(__file__).with_name('clienthello-fingerprint.py'))
fp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fp)


class DiagnosticsTests(unittest.TestCase):
    def test_cross_language_clienthello_fixture(self):
        record = bytes.fromhex((Path(__file__).resolve().parents[1]/'testdata/tls13-clienthello-v1.hex').read_text())
        result = fp.fingerprint(record)
        self.assertEqual(result['ja3_raw'], '771,4865,0-10-13-43-51-16,23,')
        self.assertEqual(result['ja3'], 'fe282bc22b5ca253a3961431d569f58d')
        self.assertEqual(result['ja4'], 't13d0106h1_0f2cb44170f4_6dca215ec8fb')
        self.assertEqual(result['alpn'], ['http/1.1'])
        for end in range(len(record)):
            with self.assertRaises(ValueError):
                fp.fingerprint(record[:end])
        with self.assertRaises(ValueError):
            fp.fingerprint(record+b'\0')

    def test_process_cpu_clock_units(self):
        self.assertEqual(cpu_seconds('01:02.50'), 62.5)
        self.assertEqual(cpu_seconds('2-03:04:05'), 183845)
        self.assertEqual(cpu_seconds('00:00.01'), .01)

    def test_validation_report_uses_observed_host_and_allows_missing_fd_metrics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def save(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            metadata = {'started_utc': '2026-10-27T00:00:00Z', 'seconds_per_phase': 60,
                        'cpu_count': 11, 'cpu_model': 'fixture CPU', 'resource_method': 'fixture RSS only',
                        'binary_sha256': {'fixture': 'same-build'}}
            account = {'reserved': 3, 'settled': 3, 'cancelled': 0, 'pending': 0, 'receipts': 3}
            for phase in ['soak', 'faults', 'profile']:
                save(root/phase/'metadata.json', metadata)
                save(root/phase/'cleanup.json', [])
            save(root/'soak/accounting.json', account)
            save(root/'faults/accounting.json', account)
            save(root/'faults/faults.json', [{'case': 'fixture', 'task': {'task_id': 'must-be-redacted', 'state': 'settled'}}])
            rows = []
            for name in ['json', 'sse', 'saturated']:
                row = {'name': name, 'admission_seconds': 60, 'succeeded': 1, 'failed': 0, 'dropped_arrivals': 0,
                       'steady_completion_rps': 1, 'mean_cpu_cores': 1, 'sum_peak_rss_mib': 10,
                       'first_content_ms': {'p50': 1, 'p95': 1, 'p99': 1},
                       'samples': [{'start_ms': 10, 'first_content_ms': 1, 'task_id': 'must-be-redacted'}]}
                rows.append({'name': name})
                save(root/f'soak/deployment/{name}.json', row)
                save(root/f'soak/deployment/{name}-resources.json', [{'seconds': 1, 'processes': {'hub': {'rss_mib': 10}}}])
            save(root/'soak/summary.json', rows)
            save(root/'profile/summary.json', [{'process_cpu_seconds': {'hub': 1, 'agent': 1, 'hub-sidecar': 2, 'provider-sidecar': 2}, 'succeeded': 3, 'failed': 0}])
            for suffix in ['top', 'cumulative']:
                (root/f'profile/go-hub-cpu-{suffix}.txt').write_text('fixture: no relay frame in top output')
            output = root/'export/result'
            subprocess.run([sys.executable, str(Path(__file__).with_name('report-production.py')),
                            '--soak', str(root/'soak'), '--faults', str(root/'faults'), '--profile', str(root/'profile'),
                            '--output', str(output)], check=True, capture_output=True)
            report = output.with_suffix('.md').read_text()
            self.assertIn('可用逻辑 CPU：11', report)
            self.assertIn('3 段各 60 秒', report)
            self.assertIn('n/a', report)
            self.assertNotIn('尚未修复', report)
            self.assertNotIn('must-be-redacted', output.with_suffix('.json').read_text())


if __name__ == '__main__':
    unittest.main()
