from bcc import BPF
from bcc.utils import printb

# Add this BPF program definition
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

BPF_PERF_OUTPUT(events);

int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
    struct event_t event = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.pid = pid;
    event.saddr = sk->__sk_common.skc_rcv_saddr;
    event.daddr = sk->__sk_common.skc_daddr;
    event.sport = sk->__sk_common.skc_num;
    event.dport = sk->__sk_common.skc_dport;

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    // Your eBPF program logic here
    return 0;
}

"""

# Load the BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect")

# Attach kprobes (kernel probes)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")

# Print trace output
print("Tracing TCP connections... Ctrl+C to exit")
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SOURCE", "DEST", "PORT"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%-6d %-12.12s %-16s %-16s %-4d" % (event.pid, event.comm,
        inet_ntop(AF_INET, pack("I", event.saddr)),
        inet_ntop(AF_INET, pack("I", event.daddr)),
        event.dport))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()