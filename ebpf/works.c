#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <linux/errno.h>
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/ns_common.h>

/*LSM_PROBE(path_chmod, const struct path *path, umode_t mode)
{
    bpf_trace_printk("Change mode of file name %s\\n", path->dentry->d_iname);
    return -1;
}*/


#define MAX_STR_LEN 412

struct mnt_namespace {
    atomic_t count;
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


LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *dat)
{
    struct task_struct *task;
    struct data_t event = {};

    task = (struct task_struct *)bpf_get_current_task();
    char first_7_chars[9];
    bpf_probe_read(first_7_chars, 9, dev_name);
    const char prefix[] = "/dev/sd";

    event.pid = bpf_get_current_pid_tgid() & 0xffffffff;
    event.tgid = bpf_get_current_pid_tgid() >> 32;

    if (true) {
        // Disallow the mount call
        bpf_trace_printk("first 7 %s", first_7_chars);
        //return -EPERM;
    }


    struct nsproxy *ns = task->nsproxy;
    struct ipc_namespace *ipc_ns = ns->ipc_ns;
    struct mnt_namespace *mnt_ns = ns->mnt_ns;
    //struct net_namespace *net_ns = ns->net_ns;
    struct pid_namespace *pid_ns = ns->pid_ns_for_children;
    //struct user_namespace *user_ns = mnt_ns->user_ns;

    //bpf_printk("ns = %u", mnt_ns->user_ns->level);

    bpf_trace_printk("Mount onto path: %s  --- %s \\n", path->dentry->d_iname, dev_name);
    return -1;
}
