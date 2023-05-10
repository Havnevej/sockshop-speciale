from bcc import BPF

# Load and attach the BPF program to the 'mount' syscall
bpf = BPF(src_file="deny_mounts.c")

bpf.trace_print()
