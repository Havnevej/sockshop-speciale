#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>



#define MAX_STR_LEN 412
#define CONTAINER_MAX_IDS 512

// the bpf array to store the container pids
BPF_ARRAY(container_pids, u32, CONTAINER_MAX_IDS);

struct new_utsname {
    char nodename[65];
};
// Not exported in kernel headers for ebpf
struct uts_namespace {
    struct new_utsname name;
    struct ns_common ns;
};


// Source for awesome BPF helper function: https://github.com/kubearmor/KubeArmor/blob/69e6f2fab246ad837af5b824a94653ee2764f948/KubeArmor/BPF/system_monitor.c#L5 
#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

typedef struct context {
    u64 ts;                     // Timestamp
    u32 pid;                    // PID as in the userspace term
    u32 tid;                    // TID as in the userspace term
    u32 ppid;                   // Parent PID as in the userspace term
    u32 host_pid;               // PID in host pid namespace
    u32 host_tid;               // TID in host pid namespace
    u32 host_ppid;              // Parent PID in host pid namespace
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[TASK_COMM_LEN];
    char uts_name[TASK_COMM_LEN];
    u32 eventid;
    s64 retval;
    u8 argnum;
} context_t;

struct pid_link {
    struct hlist_node node;
    struct pid *pid;
};
/*
These functions are from KubeArmor and are used to get the context of a task
*/
// Functions https://github.com/kubearmor/KubeArmor/blob/69e6f2fab246ad837af5b824a94653ee2764f948/KubeArmor/BPF/system_monitor.c
static __always_inline u32 get_task_ppid(struct task_struct *task)
{
    return READ_KERN(READ_KERN(task->real_parent)->pid);
}
static __always_inline u32 get_task_ns_pid(struct task_struct *task)
{
    unsigned int level = READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->level);
    return READ_KERN(READ_KERN(task->thread_pid)->numbers[level].nr);
}

static __always_inline u32 get_task_pid_vnr(struct task_struct *task)
{
    unsigned int level = 0;
    struct pid *pid = NULL;

    pid = READ_KERN(task->thread_pid);
    level = READ_KERN(pid->level);
    return READ_KERN(pid->numbers[level].nr);
}
static __always_inline u32 get_task_ns_ppid(struct task_struct *task)
{
    struct task_struct *real_parent = READ_KERN(task->real_parent);
    return get_task_pid_vnr(real_parent);
}
static __always_inline u32 get_task_ns_tgid(struct task_struct *task)
{
    struct task_struct *group_leader = READ_KERN(task->group_leader);
    return get_task_pid_vnr(group_leader);
}
static __always_inline u32 get_task_mnt_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->mnt_ns)->ns.inum);
}
static __always_inline u32 get_task_pid_ns_id(struct task_struct *task)
{
    return READ_KERN(READ_KERN(READ_KERN(task->nsproxy)->pid_ns_for_children)->ns.inum);
}
static __always_inline char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *np = READ_KERN(task->nsproxy);
    struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
    return READ_KERN(uts_ns->name.nodename);
}
/*
    Function to get the context of the current task using the functions from Kubearmor
*/
static __always_inline int init_context(context_t *context, bool print)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    if (!task){return 0;}
    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);

    // Save timestamp in microsecond resolution
    context->ts = bpf_ktime_get_ns()/1000;
    // print the values if needed
    if (print){
        bpf_trace_printk("host_tid: %d", context->host_tid);
        bpf_trace_printk("host_pid: %d", context->host_pid);
        bpf_trace_printk("host_ppid: %d", context->host_ppid);
        bpf_trace_printk("tid: %d", context->tid);
        bpf_trace_printk("pid: %d", context->pid);
        bpf_trace_printk("ppid: %d", context->ppid);
        bpf_trace_printk("mnt_id: %d", context->mnt_id);
        bpf_trace_printk("pid_id: %d", context->pid_id);
        bpf_trace_printk("uid: %d", context->uid);
        bpf_trace_printk("comm: %s", context->comm);
        bpf_trace_printk("uts_name: %s", context->uts_name);
        bpf_trace_printk("ts: %d", context->ts);
    }

    return 0;
}

/*
    The tracepoint probe to remove a pid from the list of container pids
    when the process exits
*/
TRACEPOINT_PROBE(sched, sched_process_exit)
{
    context_t context = {};
    init_context(&context, false);
    int i = 0;
    int ii = 0;
    u32 *val;
    for (i=0; i<=CONTAINER_MAX_IDS;i++){
        // Intermediate value because verifier does not know the iterator linearly increases if passed to loockup()
        ii = i;
        val = container_pids.lookup(&ii);
        if (val) {
            // check if the task originates from a container pid
            if (*val == context.host_pid) {
                container_pids.delete(&ii);
                bpf_trace_printk("pid:[%d] removed from list of container pids \n",context.host_pid);
                return  0;
            }
        } 
    }
    return 0;
}
// https://www.bluetoad.com/publication/?i=701493&article_id=3987581&view=articleBrowser
/*  
    The function to get new processes and compare them to the list of container pids, if any new process has the parent of a known container pid, add it to the list
*/
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm)
{
    context_t context = {};
    init_context(&context, false);
    int i = 0;
    int ii = 0;
    u32 *val;
    for (i=0; i<=CONTAINER_MAX_IDS;i++){
        // Intermediate value because verifier does not know the iterator linearly increases if passed to loockup()
        ii = i;
        val = container_pids.lookup(&ii);
        if (val) {
            // check if the task originates from a container pid
            if (*val == context.host_ppid) {
                int index = 0;
                for (int iii = 0; iii<=CONTAINER_MAX_IDS; iii++){
                    // We need to find an empty slot in the array
                    index = iii;
                    val = container_pids.lookup(&index);
                    if (val){
                        // update the array with new pid
                        if(*val == 0){
                            container_pids.update(&index, &context.host_pid);
                            bpf_trace_printk("add pid:[%d] to list of container pids \n",context.host_pid);
                            return  0;
                        }
                    }
                }
                return 0;
            }
        } 
    }
    return 0;
}

LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *dat)
{
    context_t context = {};
    init_context(&context, false);

    int i = 0;
    int ii = 0;
    u32 *val;
    bpf_trace_printk("container_ppid[%d] \n",context.ppid);
    for (i=0; i<=CONTAINER_MAX_IDS;i++){
        // Intermediate value because verifier does not know the iterator linearly increases if passed to loockup()
        ii=i;
        val = container_pids.lookup(&ii);
        if (val) {
            //originates from a container pid
            if (*val == context.host_ppid || *val == context.ppid) {
                bpf_trace_printk("Denied mount path: %s  --- onto %s ",dev_name ,path->dentry->d_iname);
                return -EPERM;
            }
        } 
    }
    return 0;
}
