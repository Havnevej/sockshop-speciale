#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>

/*LSM_PROBE(path_chmod, const struct path *path, umode_t mode)
{
    bpf_trace_printk("Change mode of file name %s", path->dentry->d_iname);
    return -1;
}*/
#define MAX_STR_LEN 412
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

struct cgroup_namespace {
	struct ns_common	ns;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct css_set          *root_cset;
};

struct new_utsname {
    char nodename[65];
};
struct uts_namespace {
    struct new_utsname name;
    struct ns_common ns;
};

enum event_type {
    EVENT_MOUNT,
    EVENT_MOUNT_SOURCE,
    EVENT_MOUNT_TARGET,
    EVENT_MOUNT_TYPE,
    EVENT_MOUNT_DATA,
    EVENT_MOUNT_RET,
    EVENT_UMOUNT,
    EVENT_UMOUNT_TARGET,
    EVENT_UMOUNT_RET,
};

struct data_t {
    enum event_type type;
    pid_t pid, tgid;
    union {
        /* EVENT_MOUNT, EVENT_UMOUNT */
        struct {
            /* current->nsproxy->mnt_ns->ns.inum */
            unsigned int mnt_ns;
            char comm[TASK_COMM_LEN];
            unsigned long flags;
        } enter;
        /*
         * EVENT_MOUNT_SOURCE, EVENT_MOUNT_TARGET, EVENT_MOUNT_TYPE,
         * EVENT_MOUNT_DATA, EVENT_UMOUNT_TARGET
         */
        char str[MAX_STR_LEN];
        /* EVENT_MOUNT_RET, EVENT_UMOUNT_RET */
        int retval;
    };
};


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
struct task_struct___older_v50 {
    struct pid_link pids[PIDTYPE_MAX];
};
// Functions
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
static __always_inline int init_context(context_t *context)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("test");
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

    return 0;
}

BPF_HASH(config_map, u32, u32);

static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);

    if (config == NULL)
        return 0;

    return *config;
}

BPF_PERF_OUTPUT(hey);
struct data_t2 {
    u32 pid;
    char command[16];
    char message[12];
    int mount_inum;
};

LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *dat)
{
    /*if (dev_name == NULL || path == NULL || type == NULL || flags == NULL || dat == NULL) {
        return false;
    }*/
    bpf_trace_printk("test");
    context_t context = {};
    init_context(&context);
    struct task_struct *task;
    struct data_t event = {};
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    struct cgroup_namespace *cgroup_ns;
    struct ns_common ns;
    task = (struct task_struct *)bpf_get_current_task();
    if(task){
            //bpf_trace_printk("Pid: %s ", task->real_parent->tgid);
        unsigned long flags_value = 0;
        bpf_probe_read(&flags_value, sizeof(flags_value), &task->flags);
        // Get nsproxy
        bpf_probe_read(&nsproxy, sizeof(nsproxy), &(task->nsproxy));
        if (!nsproxy) {
            bpf_trace_printk("Invalid nsproxy struct pointer");
            return -1;
        }
        // Get mount_ns
        bpf_probe_read(&mnt_ns, sizeof(mnt_ns), &(nsproxy->mnt_ns));
        if (!mnt_ns) {
            bpf_trace_printk("Invalid mnt_namespace struct pointer");
            return -1;
        }
        // Check if ns is valid before accessing inum field
        if (bpf_probe_read(&ns, sizeof(ns), &(mnt_ns->ns)) != 0) {
            //bpf_trace_printk("Invalid ns struct pointer");
            return -1;
        }

    } else {
        return -EPERM;
    }

    bpf_trace_printk("Mount namespace inum: %d", ns.inum);
    return -EPERM;
    //bpf_trace_printk("pid: %i", *task->pid);
    if (!nsproxy){
        return 0;
    }

    
    //mnt_ns = nsproxy->mnt_ns;
    struct data_t2 data = {};
    char message[12] = "Hello World";
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    //data.mount_inum=mnt_ns->ns.inum;
    hey.perf_submit(ctx, &data, sizeof(data));

    char first_7_chars[9];
    bpf_probe_read(first_7_chars, 9, dev_name);
    const char prefix[] = "/dev/sd";
    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    if (true) {
        // Disallow the mount call
        //bpf_trace_printk("first 7 %s", first_7_chars);
        //return -EPERM;
    }

    bpf_trace_printk("Mount onto path: %s  --- %s ", path->dentry->d_iname, dev_name);
    return -1;
}
