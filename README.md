# Major page faults top

## Overview

Trace major page faults with related filenames using [BPF](https://lwn.net/Articles/740157/). Sometimes you detect high rate of major faults per second (e.g., using ```sar -B 1``` command) but it's very clunky to determine which files are responsible for high IO. Standard performance tools have aggregation only per process (e.g., ```ps -eo pid,maj_flt,cmd | sort -nrk2```). But in some cases it is not enough: you may not be aware of all mapped files for instance and traversing through all fds in procfs maybe tedious and time-consuming.
It can be useful in your production environments where instances are highly dependent on *mmap()* syscall (e.g. mongodb with specific storage engine) and memory-mapped files exceed your host or container limits.

Although, there is a command in perf-tools ```perf trace -F --no-syscalls``` created with same [purpose](https://lore.kernel.org/patchwork/patch/474548/), but presented project uses modern eBPF technology which works more efficiently.

## Example output

```
$ sudo ./majortop.py                                            
TIME(ms)     PID          COMM                 INODE        ADDRESS          FILENAME     
0.4917       13407        fio                  21759123     0x7fbe57dc2000   fio-rand-read
0.1570       13407        fio                  21759123     0x7fbe8360e000   fio-rand-read
0.0920       13466        vmtouch              21642903     0x7f5b343ad000   fio-rand-RW
0.0906       13466        vmtouch              21642903     0x7f5b345e3000   fio-rand-RW
0.0932       13466        vmtouch              21642903     0x7f5b3461f000   fio-rand-RW
0.0917       13466        vmtouch              21642903     0x7f5b34653000   fio-rand-RW
```

You can generate major page faults using [fio](https://github.com/axboe/fio):

```
fio --name job1 --ioengine=mmap --rw=randread --filename=./fio-rand-read --size=1G --runtime=60
```

## Prerequisites

There is a [bcc](https://raw.githubusercontent.com/iovisor/bcc/) tool. Follow upstream [installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md) to run BPF tools. The minimal supported linux kernel version is 4.1.


## TODO

1. Add aggregation feature (top-style)
2. Add paths to filenames
