#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/pkt_cls.h>

struct bpf_map_def SEC("maps") denied_cmds = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 1024,
};

SEC("socket")
int bpf_prog1(struct __sk_buff *skb)
{
    char cmd[] = "mount";
    int *val;

    val = bpf_map_lookup_elem(&denied_cmds, &cmd);
    if (val) {
        bpf_printk("Command not allowed: %s\n", cmd);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";