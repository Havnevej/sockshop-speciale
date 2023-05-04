from bcc import BPF
import os

# Define the BPF program
program = """
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/nsproxy.h>
#include <linux/errno.h>

#define __LOWER(x) (x & 0xffffffff)
#define __UPPER(x) (x >> 32)
LSM_PROBE(path_chmod, const struct path *path, umode_t mode)
{
    bpf_trace_printk("Change mode of file name %s\\n", path->dentry->d_iname);
    return -1;
}
LSM_PROBE(sb_mount, const char *dev_name, const struct path *path,
	 const char *type, unsigned long flags, void *dat)
{
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    struct nsproxy *ns = task->nsproxy;
    struct ipc_namespace *ipc_ns = ns->ipc_ns;
    struct mnt_namespace *mnt_ns = ns->mnt_ns;
    struct net_namespace *net_ns = ns->net_ns;
    struct pid_namespace *pid_ns = ns->pid_ns_for_children;
    //struct user_namespace *user_ns = mnt_ns->user_ns;

    
    bpf_trace_printk("Mount onto path: %s  --- %s \\n", path->dentry->d_iname, dev_name);
    return -1;
}
"""

# Load and attach the BPF program to the 'mount' syscall
bpf = BPF(text=program)
bpf.trace_print()
