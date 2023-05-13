# This code is a bcc program to work alongside deny_mounts.c which denies mount syscalls originating from containers on the system
# This is for the sockshop system to disallow the mount attack vector highlighted in the thesis paper
# Import necessary libraries
from bcc import BPF
import os
from ctypes import c_int, c_uint
import docker
import threading

# Define a class for monitoring containers
class ContainerMonitor(threading.Thread):
    container_pids=[]
    containers=[]
    bpf_obj=[]

    # Define the run method
    def run(self):
        # Load initial list of containers 
        self.container_pids=self.get_container_pids_from_filesystem()
        iter=0
        for pid in self.container_pids:
            bpf["container_pids"][c_int(iter)]=c_uint(pid)
            print(f"Container pid: {pid}")
            iter+=1
        client = docker.from_env()

        # Monitor for container events
        for event in client.events(decode=True):
            if event["Type"] == "container" and event["Action"] == "create":
                self.on_container_create(event)
            if event["Type"] == "container" and event["Action"] == "start":
                self.on_container_start(event)

    # Add new containers to list of containers
    def on_container_start(self, event):
        container_id=event["Actor"]["ID"]
        print("New container started:", event["Actor"]["ID"])
        pids=self.get_pids_from_proc_file(container_id)
        self.container_pids=self.container_pids+pids
        for pid in pids:
            self.update_container_pids_in_map(pid)

    # Add new containers to list of containers
    def on_container_create(self, event):
        container_id=event["Actor"]["ID"]
        print("New container created:", event["Actor"]["ID"])
        self.containers.append(container_id)

    # Get pids from proc file
    def get_pids_from_proc_file(self, container_id):
        container_pids = []
        with open(f'/sys/fs/cgroup/system.slice/docker-{container_id}.scope/cgroup.procs', 'r') as procs_file:
            for pid in procs_file:
                container_pids.append(int(pid.strip()))
        return container_pids
    
    # Get container pids from filesystem
    def get_container_pids_from_filesystem(self):
        container_pids = []
        for file in os.listdir('/sys/fs/cgroup/system.slice/'):
            if file.startswith('docker-') and file.endswith('.scope'):
                container_id=file.split("docker-")[1].split(".scope")[0]
                container_pids=container_pids+self.get_pids_from_proc_file(container_id)
        return container_pids

    # Update container pids in map
    def update_container_pids_in_map(self, pid):
        iter=0
        for existing_pid in self.bpf_obj["container_pids"]:
            if self.bpf_obj["container_pids"][existing_pid] != c_uint(0):
                self.bpf_obj["container_pids"][c_int(iter)]=c_uint(pid)
                print(c_uint(pid))
                return
            iter+=1

# Create an ebpf map to store container pids
bpf = BPF(src_file="deny_mounts.c")

# Create a container monitor thread
monitor_thread = ContainerMonitor()
monitor_thread.bpf_obj=bpf
monitor_thread.start()

# Print trace
bpf.trace_print()


