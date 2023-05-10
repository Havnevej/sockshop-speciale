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

struct cgroup_namespace {
	struct ns_common	ns;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	struct css_set          *root_cset;
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

BPF_PERF_OUTPUT(hey);
struct data_t2 {
    u32 pid;
    char command[16];
    char message[12];
    int mount_inum;
};

static __always_inline void test_func(){

    

}

LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *dat)
{
    if (dev_name == NULL || path == NULL || type == NULL || flags == NULL || dat == NULL) {
        return false;
    }
    struct task_struct *task;
    struct data_t event = {};
    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    task = (struct task_struct *)bpf_get_current_task();
    if(task){
        nsproxy = task->nsproxy;
    }
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

    bpf_trace_printk("Mount onto path: %s  --- %s \\n", path->dentry->d_iname, dev_name);
    return -1;
}
