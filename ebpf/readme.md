# README for deny_mount eBPF Program
## Introduction

This README provides instructions on how to run the deny_mount eBPF program using two different approaches:

    The BCC Python approach
    The manual approach using the Clang compiler directly

## Prerequisites

Before proceeding, ensure you have the following installed:

  -  Python 3
  -  BCC (BPF Compiler Collection)
  -  Clang and LLVM
  -  Linux kernel headers

## BCC Python Approach
### Step 1: Install BCC

First, you need to install the BCC library. You can do this using the package manager for your Linux distribution. For example, on Ubuntu, you would use the following command:
```bash
sudo apt-get install bpfcc-tools python3 python3-bpfcc
sudo python3 -m pip install bcc
```

### Step 2: Run the Program
Navigate to the directory containing the deny_mount.py and deny_mount.c files. Run the Python script with sudo privileges:
```bash
sudo python3 deny_mount.py
```
This will compile the deny_mount.c eBPF program and load it into the kernel, where it will start monitoring for mount system calls and deny them.

## Manual Approach Using Clang Compiler
### Step 1: Compile the eBPF Program
Navigate to the directory containing the deny_mount.c file. Use the Clang compiler to compile the eBPF program:
```bash
clang -O2 -target bpf -c deny_mount.c -o deny_mount.o
```
This command will generate a deny_mount.o file, which is the compiled eBPF program.
### Step 2: Load the eBPF Program into the Kernel
To load the eBPF program into the kernel, you can use the bpftool command. First, you need to get the program ID:
```bash
bpftool prog load deny_mount.o /sys/fs/bpf/deny_mount
```

### Step 3: Attach the eBPF Program to a Hook Point

Finally, you need to attach the eBPF program to a hook point in the kernel. For this, you can use the bpftool command again:

```bash
bpftool cgroup attach /sys/fs/cgroup/unified/ cgroup1 deny_mount
```
This command will attach the deny_mount eBPF program to the cgroup's mount syscall, effectively denying mount operations.

# Conclusion
Both approaches will run the deny_mount eBPF program, which will monitor for mount system calls and deny them. The BCC Python approach is simpler and more automated, while the manual approach using the Clang compiler gives you more control over the process. 