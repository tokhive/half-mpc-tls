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
                                          'fd_median':statistics.median([f['processes'][name]['fds'] for f in frames]),
                                          'thread_peak':max(f['processes'][name]['threads'] for f in frames)}
                                     for name in frames[0]['processes']} if frames else {}})
    full['minutes']=minutes
    return full


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['soak','faults','profile']:
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('docs/performance/production-validation-2026-10-26'))
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
    relay_percent=next(line.split()[-2] for line in cpu_cumulative.splitlines() if line.endswith('precompute.relayMPC.func2'))
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
    lines=['# 本机生产前验证：持续负载与故障恢复','',
           f"测量开始：{metas['soak']['started_utc']}。2 个逻辑 CPU，真实四进程、TLS 1.3、合成 HTTPS 上游。",'',
           '## 验收范围','',
           '本轮用于检验本机稳定性、错误退出、重连和账本一致性。先复现并修复三个故障，再以相同最终二进制完成故障复测、Go CPU profile 和连续负载。仅完成 15 分钟连续负载，不是 24 小时或多天 soak；不包含真实模型、跨机公网、带宽限制或丢包。用户已明确将跨机验证留到后续。', '',
           '## 实际发现与修复','',
           '1. **Hub 崩溃遗留 pending 余额预留。** 在已收到 SSE 内容后 SIGKILL Hub，原实现重启后任务仍 pending。启动流程现先重放持久回执，再取消其余中断任务并退款，最后开放 API；重复重启不重复退款。已有回执必须优先结算，不能先批量退款。',
           '2. **传输故障留下阻塞的响应读取。** Agent 在流式处理中退出后，原实现只取消转发 context，客户端等到 35 秒读取超时，任务仍 pending。现对失败会话异步关闭全部附件，解除响应阻塞；初始化时保持任务计数非零，防止首个任务立即失败时与其余任务注册竞争。',
           '3. **响应阶段未受总请求期限约束。** 现将原请求 deadline 绑定到会话销毁，客户端断开后的继续读取和结算也不超过该期限。合成上游持续输出的测试在约 25 秒被终止、退款，没有输出 DONE。', '',
           'Hub 重启后的取消表示缺少可靠结算证据，不表示上游未处理请求。上游可能已经产生费用；本地不会对不完整响应计费。原任务键保留，SDK 不会自动重新执行。', '',
           '## 故障复测','',
           '| 场景 | 恢复/结束时间 | 账本结果 |',
           '| --- | ---: | --- |']
    for f in faults:
        timing=f"{f['ready_ms']/1000:.3f} 秒" if 'ready_ms' in f else f"{f['elapsed_seconds']:.3f} 秒" if 'elapsed_seconds' in f else '响应读完后'
        state=f.get('task',{}).get('state','原结算保持不变')
        lines.append(f"| {f['case']} | {timing} | {state} |")
    lines += ['',
              '恢复时间是单次观察，不是恢复 SLA。每个强制重启均发生在收到首条真实 SSE 内容之后；不是空闲进程重启。进程由测试 supervisor 拉起，sidecar 的残留 UDS 由 supervisor 在确认旧进程退出后清理。产品进程自身没有自动拉起功能。',
              '数据链路中断覆盖所有 Provider 数据 TCP 连接，拒绝新连接 3 秒后恢复；控制连接保留。表中时间包含这 3 秒，属于应用层断链模拟，不是丢包模拟。每次强制重启后完成 6 个成功请求，数据链路恢复后完成 3 个成功请求。客户端主动断流的响应会继续认证读完并结算。',
              f"故障场景账本：预留 {fault_accounting['reserved']}，结算 {fault_accounting['settled']}，取消 {fault_accounting['cancelled']}，pending {fault_accounting['pending']}；回执 {fault_accounting['receipts']}。同一任务不重复结算、结算与取消集合不相交。",'',
              '**健康策略观察：** 最初连续注入多个故障、每次仅完成 3 个成功请求时，累计健康分达到 11，触发已有的 5 分钟隔离，ready 等待超过 120 秒。这是持久化隔离策略，不是数据连接没有重连。最终复测在每次故障后完成 6 个成功请求以恢复健康分，区分单次网络恢复与连续失败隔离；没有降低健康校验或隔离阈值。','',
              '## 15 分钟连续负载','',
              '同一部署连续执行三段各 300 秒负载，期间不重启或清空池。上游首响应等待 200 ms；SSE 为 40 个内容事件、间隔 20 ms；小请求为 1 KiB prompt。预热目标 2、上限 4、预热并发 2，等待队列上限 64、等待 10 秒，总请求期限 25 秒。', '',
              '| 场景 | 成功/失败/发压端未发送 | 首内容 P50/P95/P99 ms | 稳态完成/s | 四进程 CPU 核数 | RSS 峰值 MiB |',
              '| --- | ---: | ---: | ---: | ---: | ---: |']
    for r in rows:
        p=r['first_content_ms']
        lines.append(f"| {r['name']} | {r['succeeded']}/{r['failed']}/{r['dropped_arrivals']} | {p['p50']:.0f}/{p['p95']:.0f}/{p['p99']:.0f} | {r['steady_completion_rps']:.2f} | {r['mean_cpu_cores']:.2f} | {r['sum_peak_rss_mib']:.0f} |")
    lines += ['',f"持续负载账本：预留 {accounting['reserved']}，结算 {accounting['settled']}，取消 {accounting['cancelled']}，pending {accounting['pending']}；回执 {accounting['receipts']}。",'',
              '成功分位数不包含失败；所有失败和未发送均单列。JSON 首内容表示完整 JSON 解析完成，SSE 表示首个非空内容事件。稳态完成速率去掉每段前 10 秒和末尾排空。', '',
              '## 分钟窗口与资源','',
              '每 250 ms 采样四服务的 RSS、文件描述符和线程数。RSS 合计可能重复计入共享页；未包含上游、负载生成器和 Python harness。窗口按请求开始时间划分；内存是该分钟采样中位数。不同阶段工作负载及预热库存不同，不能只比较首尾 RSS 就判定泄漏。持久账本任务索引本身也随任务数增长。', '',
              '| 场景/分钟 | 成功/失败 | 首内容 P95 ms | 合计 RSS 中位数 MiB | Hub / Agent / 两 sidecar FD 中位数 |',
              '| --- | ---: | ---: | ---: | --- |']
    for r in rows:
        for m in r['minutes']:
            procs=m['processes']
            fds=' / '.join(str(procs[n]['fd_median']) for n in ['hub','agent','hub-sidecar','provider-sidecar'])
            lines.append(f"| {r['name']} / {m['minute']} | {m['success']}/{m['failed']} | {m['first_content_p95_ms']:.0f} | {m['rss_median_mib']:.0f} | {fds} |")
    lines += ['',
              '本轮观察到持续内存增长：Agent 每分钟 RSS 中位数从约 15 MiB 升至 105 MiB，四服务合计中位数从 177 MiB 升至 338 MiB，峰值 444 MiB。各阶段 FD 中位数保持稳定，不能据此排除 goroutine/连接对象泄漏。代码核查发现 internal/tunnel/provider.go 的 Serve 在每次连接建立时创建等待 Agent 全局 context 结束的 goroutine，连接退出不会移除它。新增回归实测 128 个已关闭连接留下 128 个 goroutine，测试失败，日志 /tmp/tokenhive-agent-leak-before.log。该问题尚未修复，不能判定长期稳定性通过。用户随后要求停止测试，本轮到此停止，未启动下一轮压测。', '',
              '## CPU profile','',
              '独立 60 秒、4 并发场景，通过公开 hub.RunFile 包装器采集 Go CPU profile，没有打开调试 HTTP 端口。系统 perf_event_paranoid=4 禁止 perf，未改变系统设置；本轮没有 Rust 原生调用栈采样，也没有声称完成全部 MPC 内部阶段的 CPU 归因。', '',
              f"Hub CPU 样本中，经 MPC 转发路径 relayMPC 的累计占比为 {relay_percent}；两个 Rust sidecar 合计占四服务 CPU 时间约 {sidecar_percent:.1f}%。Go 的下一优化方向是转发路径中的帧分配、复制和 I/O；Rust 仍需原生 profile 才能继续分解。", '',
              f"四进程 CPU 秒数：{json.dumps(profile['process_cpu_seconds'],ensure_ascii=False)}。该 profile 场景成功 {profile['succeeded']}、失败 {profile['failed']}。",'',
              f"[Hub CPU 平面采样]({args.output.name}-cpu-top.txt) · [累计调用路径]({args.output.name}-cpu-cumulative.txt)。累计路径有包含关系，百分比不可相加。原始 pprof 保存在 `{args.profile}` 下。",'',
              '## 校验与复现','',
              'Go race 全套、go vet、默认 TLS 1.2 四进程 JSON/SSE/SDK 冒烟均通过。新增回归覆盖已落盘未结算回执与无回执任务的恢复顺序、重复重启和退款幂等性、断链解除响应阻塞、任务初始化与关闭竞争、响应期限及健康分处理。', '',
              '```sh',
              'make build',
              'go build -trimpath -o bin/tokenhive-loadtest ./scripts/loadtest',
              'go build -trimpath -o bin/tokenhive-profile-hub ./scripts/profilehub',
              'python3 scripts/validate-production.py --mode faults',
              'python3 scripts/validate-production.py --mode profile',
              'python3 scripts/validate-production.py --mode soak --seconds 300',
              '```','',
              f"原始数据：持续负载 `{args.soak}`；故障 `{args.faults}`；CPU `{args.profile}`。三个阶段记录的构建产物 SHA-256 一致；profile 使用独立诊断包装器，记录在 [JSON 导出]({args.output.name}.json)。被测进程退出和 socket 清理均通过。",'',
              '本轮未通过长期稳定性验收：Agent 连接生命周期泄漏待修复。生产容量验收仍缺少跨机实际 RTT、真实模型、大规模并发、24 小时以上运行和生产 supervisor 部署验证。吞吐提升需要另行优化；本轮优先修复了可用性与结算恢复缺口。','']
    args.output.with_suffix('.md').write_text('\n'.join(lines))
    print(args.output.with_suffix('.md'))


if __name__=='__main__':main()
