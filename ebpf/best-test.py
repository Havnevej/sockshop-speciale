from bcc import BPF

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

int deny_mount(struct pt_regs *ctx) {
    u64 cgroup_id = bpf_get_current_cgroup_id();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = task->real_parent;
    bpf_trace_printk("id %d", cgroup_id);
    bpf_trace_printk("parent %d", parent->pid);
    if (cgroup_id != 0) {
        bpf_trace_printk("Hello, World!\\n");
        return -1;
    }
    bpf_trace_printk("Hello, World2!\\n");
    return 0;
}
"""

b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("mount"), fn_name="deny_mount")
# Print the output of the eBPF program to the console
b.trace_print()