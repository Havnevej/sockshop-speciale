#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char path[DNAME_INLINE_LEN];
};

BPF_PERF_OUTPUT(events);

int trace_sys_mount(struct pt_regs *ctx, const char __user *dev_name,
                    const char __user *dir_name,
                    const char __user *type, unsigned long flags,
                    void __user *data)
{
    struct data_t data = {};
    struct task_struct *task;
    u32 pid = bpf_get_current_pid_tgid();

    task = (struct task_struct *)bpf_get_current_task();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.pid = pid;

    if (bpf_probe_read(&data.path, sizeof(data.path), (void *)dir_name)) {
        return 0;
    }

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}