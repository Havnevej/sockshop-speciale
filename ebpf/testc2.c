#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <uapi/linux/ptrace.h>
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char container_id[32];
    char syscall[32];
    u64 args[6];
};

BPF_PERF_OUTPUT(events);

int syscall_enter(struct pt_regs *ctx)
{
    u64 id = ctx->ax;
    struct task_struct *task;
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    struct namespace *ns;
    char container_id[32] = {0};

    if (id != __NR_clone)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    bpf_probe_read(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
    bpf_probe_read(&ns, sizeof(ns), &mnt_ns->ns);
    bpf_probe_read(&container_id, sizeof(container_id), &ns->name);

    if (strcmp(ns->type, "pid") != 0)
        return 0;

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&data.args, sizeof(data.args), &ctx->di);
    bpf_probe_read(&data.args[1], sizeof(data.args[1]), &ctx->si);
    bpf_probe_read(&data.args[2], sizeof(data.args[2]), &ctx->dx);
    bpf_probe_read(&data.args[3], sizeof(data.args[3]), &ctx->r10);
    bpf_probe_read(&data.args[4], sizeof(data.args[4]), &ctx->r8);
    bpf_probe_read(&data.args[5], sizeof(data.args[5]), &ctx->r9);
    bpf_probe_read(&data.container_id, sizeof(data.container_id), &container_id);
    bpf_probe_read(&data.syscall, sizeof(data.syscall), &id);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
