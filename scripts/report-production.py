#!/usr/bin/env python3
"""Export local validation evidence without generated credentials or task IDs."""
import argparse
import json
import math
from pathlib import Path
import statistics


def read(path):
    return json.loads(path.read_text())


def percentile(values, quantile):
    values=sorted(values)
    return values[math.ceil(len(values)*quantile)-1] if values else 0


def optional_stat(frames, name, field, aggregate):
    values = [f['processes'][name][field] for f in frames if field in f['processes'][name]]
    return aggregate(values) if values else None


def phase(root,row):
    path=next(root.glob('*/'+row['name']+'.json'))
    full=read(path)
    for sample in full['samples']:
        sample.pop('task_id',None)
    resources=read(path.with_name(row['name']+'-resources.json'))
    minutes=[]
    for minute in range(math.ceil(full['admission_seconds']/60)):
        samples=[s for s in full['samples'] if minute*60000<=s['start_ms']<(minute+1)*60000]
        success=[s for s in samples if not s.get('error')]
        frames=[f for f in resources if minute*60<=f['seconds']<(minute+1)*60]
        totals=[sum(p['rss_mib'] for p in f['processes'].values()) for f in frames]
        minutes.append({'minute':minute+1,'success':len(success),'failed':len(samples)-len(success),
                        'first_content_p95_ms':percentile([s['first_content_ms'] for s in success],.95),
                        'rss_median_mib':statistics.median(totals) if totals else 0,
                        'rss_peak_mib':max(totals,default=0),
                        'processes':{name:{'rss_median_mib':statistics.median([f['processes'][name]['rss_mib'] for f in frames]),
                                          'fd_median':optional_stat(frames, name, 'fds', statistics.median),
                                          'thread_peak':optional_stat(frames, name, 'threads', max)}
                                     for name in frames[0]['processes']} if frames else {}})
    full['minutes']=minutes
    return full


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['soak','faults','profile']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True, help='new output stem; historical reports are never overwritten by default')
    args=parser.parse_args()
    for root in [args.soak,args.faults,args.profile]:
        assert read(root/'cleanup.json')==[], f'cleanup failed: {root}'
    rows=[phase(args.soak,row) for row in read(args.soak/'summary.json')]
    assert len(rows)==3
    accounting=read(args.soak/'accounting.json')
    fault_accounting=read(args.faults/'accounting.json')
    assert accounting['pending']==fault_accounting['pending']==0
    faults=read(args.faults/'faults.json')
    for fault in faults:
        if 'task' in fault:fault['task'].pop('task_id',None)
    profile=read(args.profile/'summary.json')[0]
    cpu_cumulative=(args.profile/'go-hub-cpu-cumulative.txt').read_text()
    relay_percent=next((line.split()[-2] for line in cpu_cumulative.splitlines() if line.endswith('precompute.relayMPC.func2')), None)
    sidecar_percent=100*sum(profile['process_cpu_seconds'][n] for n in ['hub-sidecar','provider-sidecar'])/sum(profile['process_cpu_seconds'].values())
    metas={name:read(getattr(args,name)/'metadata.json') for name in ['soak','faults','profile']}
    assert metas['soak']['binary_sha256']==metas['faults']['binary_sha256']==metas['profile']['binary_sha256']
    exported={'metadata':metas,'soak':rows,'faults':faults,'soak_accounting':accounting,
              'fault_accounting':fault_accounting,'profile':profile,'cleanup':[]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.with_suffix('.json').write_text(json.dumps(exported,indent=2)+'\n')
    for suffix in ['top','cumulative']:
        text=(args.profile/f'go-hub-cpu-{suffix}.txt').read_text()
        args.output.with_name(args.output.name+f'-cpu-{suffix}.txt').write_text(text)
    host = metas['soak']
    seconds = host['seconds_per_phase']
    lines = ['# 本机持续负载与恢复验证', '',
             f"测量开始：{host['started_utc']}；CPU：{host.get('cpu_model', 'unknown')}，可用逻辑 CPU：{host['cpu_count']}。", '',
             f"同一部署执行 {len(rows)} 段各 {seconds} 秒负载。真实四进程、合成 HTTPS 上游、生成凭证；不是付费模型、跨机或 24 小时验收。", '',
             '## 故障恢复', '', '| 场景 | 观察耗时 | 任务状态 |', '| --- | ---: | --- |']
    for f in faults:
        timing = f"{f['ready_ms']/1000:.3f} 秒" if 'ready_ms' in f else f"{f['elapsed_seconds']:.3f} 秒" if 'elapsed_seconds' in f else '响应读完后'
        lines.append(f"| {f['case']} | {timing} | {f.get('task', {}).get('state', '保持原结算')} |")
    lines += ['', '恢复耗时是本次观察，不是 SLA。重启由测试 supervisor 执行，数据分区是应用层断链，不是包级丢包模拟。',
              f"故障账本：{json.dumps(fault_accounting, ensure_ascii=False)}。", '',
              '## 持续负载', '',
              '| 场景 | 成功/失败/未发送 | 首内容 P50/P95/P99 ms | 稳态完成/s | 四进程 CPU 核数 | RSS 峰值 MiB |',
              '| --- | ---: | ---: | ---: | ---: | ---: |']
    for row in rows:
        p = row['first_content_ms']
        lines.append(f"| {row['name']} | {row['succeeded']}/{row['failed']}/{row['dropped_arrivals']} | {p['p50']:.0f}/{p['p95']:.0f}/{p['p99']:.0f} | {row['steady_completion_rps']:.2f} | {row['mean_cpu_cores']:.2f} | {row['sum_peak_rss_mib']:.0f} |")
    lines += ['', f"持续负载账本：{json.dumps(accounting, ensure_ascii=False)}。", '',
              '成功延迟分位数只统计成功请求；失败和未发送数量单列。JSON 首内容指完整 JSON，SSE 指首个内容事件。', '',
              '## 分钟资源窗口', '',
              f"采样方法：{host.get('resource_method', '原始报告方法')}。缺失的 FD/线程指标标为 n/a，不补零。RSS 合计可能重复计算共享页，且账本任务索引随任务数增长。", '',
              '| 场景/分钟 | 成功/失败 | 首内容 P95 ms | RSS 合计中位数 MiB | Hub / Agent / Hub sidecar / Provider sidecar RSS 中位数 MiB | 同顺序 FD 中位数 |',
              '| --- | ---: | ---: | ---: | --- | --- |']
    for row in rows:
        for minute in row['minutes']:
            procs = minute['processes']
            fds = ' / '.join(str(procs.get(name, {}).get('fd_median')) if procs.get(name, {}).get('fd_median') is not None else 'n/a' for name in ['hub', 'agent', 'hub-sidecar', 'provider-sidecar'])
            rss = ' / '.join(f"{procs[name]['rss_median_mib']:.1f}" if name in procs else 'n/a' for name in ['hub', 'agent', 'hub-sidecar', 'provider-sidecar'])
            lines.append(f"| {row['name']} / {minute['minute']} | {minute['success']}/{minute['failed']} | {minute['first_content_p95_ms']:.0f} | {minute['rss_median_mib']:.0f} | {rss} | {fds} |")
    lines += ['', '资源曲线用于观察本次窗口；不能凭 FD 稳定或 RSS 首尾差值独立判定泄漏。', '',
              '## Go CPU profile', '',
              f"MPC 转发累计占比：{relay_percent or '未在本次 top 输出中单列'}；两个 sidecar 占四进程 CPU 约 {sidecar_percent:.1f}%。累计路径有包含关系，不可相加。", '',
              f"四进程 CPU 秒数：{json.dumps(profile['process_cpu_seconds'])}；成功 {profile['succeeded']}，失败 {profile['failed']}。", '',
              f"[平面采样]({args.output.name}-cpu-top.txt) · [累计采样]({args.output.name}-cpu-cumulative.txt) · [脱敏数据]({args.output.name}.json)。Rust 分阶段及原生栈另由 profile-warm.py 记录，本报告不假定其已执行。", '',
              '## 一致性与范围', '',
              '已检查三个阶段的构建产物 SHA-256 一致、清理无异常、任务无重复结算及未决 pending。具体失败请求仍保留在数据中；本报告不会自动声称 Go/Rust 测试或生产稳定性通过。', '',
              f"原始目录：soak `{args.soak}`，faults `{args.faults}`，profile `{args.profile}`。原目录含生成配置与私钥，分享脱敏导出即可。", '',
              '真实 Provider 出口、真实凭证与模型、跨机 RTT/带宽/丢包和长时间运行需要独立准入验证。', '']
    args.output.with_suffix('.md').write_text('\n'.join(lines))
    print(args.output.with_suffix('.md'))


if __name__=='__main__':main()
