#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
#include <linux/pkt_cls.h>

struct bpf_map_def SEC("maps") denied_cmds = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(char),
    .value_size = sizeof(int),
    .max_entries = 1024,
};

SEC("kprobe/sys_mount")
int bpf_prog1(struct pt_regs *ctx)
{
    char cmd[] = "mount";
    int *val;

    val = bpf_map_lookup_elem(&denied_cmds, cmd);
    if (val) {
        bpf_printk("Command not allowed: %s\n", cmd);
        return -1;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";