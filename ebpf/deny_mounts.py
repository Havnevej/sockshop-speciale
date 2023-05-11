from bcc import BPF
import os
from ctypes import c_int
def get_container_pids():
    container_pids = []
    for file in os.listdir('/sys/fs/cgroup/system.slice/'):
        if file.startswith('docker-') and file.endswith('.scope'):
            with open(f'/sys/fs/cgroup/system.slice/{file}/cgroup.procs', 'r') as procs_file:
                for pid in procs_file:
                    container_pids.append(int(pid.strip()))
    return container_pids

 
# Create an ebpf map to store container pids
bpf = BPF(src_file="deny_mounts.c")
container_pids = get_container_pids()
container_pids_bpf_map=bpf["container_pids"]
iter=0
for pid in container_pids:
    bpf["container_pids"][c_int(iter)]=c_int(pid)
    iter+=1
# Load and attach the BPF program to the 'mount' syscall

bpf.trace_print()
