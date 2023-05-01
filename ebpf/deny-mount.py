# Import the necessary BCC modules
from bcc import BPF

# Define the eBPF program
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int deny_mount(struct pt_regs *ctx, const char __user *pathname, int flags) {
    char buf[256];
    bpf_probe_read_user(buf, sizeof(buf), pathname);
    if (strstr(buf, "mount") != NULL) {
        u64 cgroup_id = bpf_get_current_cgroup_id();
        if (cgroup_id != 0) {
            return -1;
        }
    }
    return 0;
}
"""


# Load the eBPF program
b = BPF(text=prog)

# Attach the eBPF program to the mount syscall
b.attach_kprobe(event="do_mount", fn_name="deny_mount")
