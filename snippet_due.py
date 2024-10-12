from bcc import BPF

bpf_program = """
#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32);

int trace_open_entry(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int trace_open_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);
    if (tsp != NULL) {
        u64 delta = bpf_ktime_get_ns() - *tsp;
        bpf_trace_printk("open took %d ns\\n", delta);
        start.delete(&pid);
    }
    return 0;
}
"""

# Load the BPF program
b = BPF(text=bpf_program)

# Attach kprobes (kernel probes)
b.attach_kprobe(event="do_sys_open", fn_name="trace_open_entry")
b.attach_kretprobe(event="do_sys_open", fn_name="trace_open_return")

# Print trace output
print("Tracing open() syscall... Ctrl+C to exit")
b.trace_print()