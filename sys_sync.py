from bcc import BPF
import sys
print("Tracing sys_sync()... Ctrl-C")
try:
    BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("Hello world!\\n"); return 0;}').trace_print()
except KeyboardInterrupt:
    sys.exit(0)