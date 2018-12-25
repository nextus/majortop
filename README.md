# Major page faults top

## Overview

Trace major page faults with related filenames using [BPF](https://lwn.net/Articles/740157/). Sometimes you detect high rate of major faults per second (e.g., using ```sar -B 1``` command) but it's very clunky to determine which files are responsible for high IO. Standard performance tools have aggregation only per process (e.g., ```ps -eo pid,maj_flt,cmd | sort -nrk2```). But in some cases it is not enough: you may not be aware of all mapped files for instance and traversing through all fds in procfs maybe tedious and time-consuming.
It can be useful in your production environments where instances are highly dependent on *mmap()* syscall (e.g. mongodb with specific storage engine) and memory-mapped files exceed your host or container limits.

Although, there is a command in perf-tools ```perf trace -F --no-syscalls``` created with same [purpose](https://lore.kernel.org/patchwork/patch/474548/), but presented project uses modern eBPF technology which works more efficiently.

## Example output

```
$ sudo ./majortop.py                                            
TIME(ms)     PID          COMM                 INODE        ADDRESS          DEVICE    FILENAME
0.1071       20637        fio                  21762985     0x7f2dd08da000   254:2     nextus/dev/fio.jobs/file3.0.0
0.1097       20635        fio                  21762968     0x7f2dbe0f4000   254:2     nextus/dev/fio.jobs/file1.0.0
0.1272       20636        fio                  21762983     0x7f2dc1851000   254:2     nextus/dev/fio.jobs/file2.0.0
0.1015       20637        fio                  21762985     0x7f2dbf9c1000   254:2     nextus/dev/fio.jobs/file3.0.0
0.1022       20636        fio                  21762983     0x7f2dc4631000   254:2     nextus/dev/fio.jobs/file2.0.0
0.1044       20635        fio                  21762968     0x7f2de5b37000   254:2     nextus/dev/fio.jobs/file1.0.0
0.1119       20637        fio                  21762985     0x7f2dab1a3000   254:2     nextus/dev/fio.jobs/file3.0.0
```

You can generate major page faults using [fio](https://github.com/axboe/fio):

```
fio --name job1 --ioengine=mmap --rw=randread --filename=./fio-rand-read --size=1G --runtime=60
```

## Prerequisites

There is a [bcc](https://raw.githubusercontent.com/iovisor/bcc/) tool. Follow upstream [installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md) to run BPF tools. The minimal supported linux kernel version is 4.1.


## File path resolution

There is a limitation in BPF itself about maximum stack size, so you have to specify maximum depth of file path resolution (MAXDEPTH) or use default value (which is 5 iterations). You should set moderate amount, otherwise, the program won't start due to overflowing.
File path resolution works only within specific mount namespace. You can use major and minor device ids to determine specific partition related to specific major fault.



## TODO

1. Add aggregation feature (top-style)
