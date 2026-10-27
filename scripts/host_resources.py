"""Bounded Linux/macOS resource observations; no process arguments or environment."""
import os
from pathlib import Path
import platform
import re
import subprocess


def cpu_seconds(value):
    days, _, clock = value.rpartition('-')
    parts = [float(part) for part in clock.split(':')]
    total = 0
    for part in parts:
        total = total * 60 + part
    return total + (int(days) * 86400 if days else 0)


def proc_stats(pid):
    try:
        if platform.system() == 'Darwin':
            fields = subprocess.check_output(
                ['ps', '-p', str(int(pid)), '-o', 'time=,rss='], text=True,
                stderr=subprocess.DEVNULL, timeout=2).split()
            return {'cpu_seconds': cpu_seconds(fields[0]), 'rss_mib': int(fields[1])/1024}
        fields = Path(f'/proc/{int(pid)}/stat').read_text().split(') ', 1)[1].split()
        return {'cpu_seconds': (int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK'),
                'rss_mib': int(fields[21])*os.sysconf('SC_PAGE_SIZE')/(1 << 20),
                'threads': int(fields[17]), 'fds': len(list(Path(f'/proc/{int(pid)}/fd').iterdir()))}
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        # Missing observations must not become plausible-looking zero measurements.
        raise RuntimeError(f'cannot sample owned process {pid}') from None


def available_mib():
    if platform.system() == 'Darwin':
        output = subprocess.check_output(['vm_stat'], text=True, timeout=2)
        page_size = int(re.search(r'page size of (\d+) bytes', output).group(1))
        pages = {name: int(count) for name, count in re.findall(r'^([^:]+):\s+(\d+)\.', output, re.M)}
        # Conservative reclaimable estimate; not equivalent to Linux MemAvailable.
        return (pages.get('Pages free', 0) + pages.get('Pages inactive', 0))*page_size/(1 << 20)
    fields = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    return int(fields['MemAvailable'].split()[0])/1024


def host_metadata():
    if platform.system() == 'Darwin':
        def sysctl(name):
            return subprocess.check_output(['sysctl', '-n', name], text=True, timeout=2).strip()
        return {'cpu_count': os.cpu_count(), 'cpu_model': sysctl('machdep.cpu.brand_string'),
                'mem_total_kib': int(sysctl('hw.memsize'))//1024,
                'resource_method': 'ps time/rss; vm_stat free+inactive estimate; threads/fds not sampled'}
    return {'cpu_count': len(os.sched_getaffinity(0)),
            'cpu_model': next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
            'mem_total_kib': int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))),
            'resource_method': '/proc process stat/fd and MemAvailable'}
