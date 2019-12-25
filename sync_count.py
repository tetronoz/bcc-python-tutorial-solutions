from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    u64 count, *countp, count_key = 1;

    countp = last.lookup(&count_key);
    if (countp != 0) {
        count = *countp + 1;
        last.delete(&count_key);
    } else {
        count = 1;
    }
    last.update(&count_key, &count);

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("%d %d\\n", delta / 1000000, count);
        } else {
            bpf_trace_printk("%d\\n", count);
        }
        last.delete(&key);
    }
    
    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        if start == 0:
            start = ts
        ts = ts - start
        if len(msg.split()) == 2:
            ms, count = msg.split()
            printb("At time %.2f s: multiple syncs detected, last %s ms ago, total calls: %s" % (ts, ms, count))
        else:
            printb("No fast calls detected. Total calls: %s" % (msg))
    except KeyboardInterrupt:
        exit()