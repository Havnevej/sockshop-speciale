# Compiling
sudo clang -O2 -target bpf -c deny-mount.c -o deny-mount.o

# Running
sudo bpftool prog load deny-mount.o /sys/fs/bpf/denied_cmds