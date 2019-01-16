#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# majortop Trace major pagefaults with related filenames.
#          For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: majortop [-h] [-f]
#
# You have to specify maximum depth of file path resolution (MAXDEPTH).
# You should set moderate amount, otherwise, the program won't start. Default is 5.
# File path resolution works only within specific mount namespace.
#
# It's initial release without aggregation feature.

import sys, os
import locale
import argparse
import functools
import ctypes as ct
import struct
import time

from subprocess import call
from collections import namedtuple, Counter
from bcc import BPF

EXAMPLES = """examples:
    ./majortop           # trace all major faults
    ./majortop -p 181    # only trace PID 181
    ./majortop -f        # follow mode
"""
DEBUG = 0


loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <linux/mm.h>
#include <linux/mount.h>

enum event_type {
    EVENT_RET,
    EVENT_PATH,
};

struct data_t {
    u32 pid;
    enum event_type type;
    u64 delta;
    u64 inode;
    char comm[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
    u64 address;
    unsigned int major;
    unsigned int minor;
};

struct val_t {
    struct vm_fault *vmf;
    u64 ts;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(faults, u32, struct val_t);

int fault_handle_start(struct pt_regs *ctx, struct vm_fault *vmf) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    struct val_t val = {};
    val.vmf = vmf;
    val.ts = bpf_ktime_get_ns();
    
    faults.update(&pid, &val);

    return 0;
}

int fault_handle_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    struct val_t *val = faults.lookup(&pid);
    if (val == 0)
        return 0;
 
    vm_fault_t retcode = PT_REGS_RC(ctx);
    if ( !(retcode & VM_FAULT_MAJOR)) {
        faults.delete(&pid);
        return 0;    
    }

    struct data_t data = {};
    data.pid = pid;
    data.delta = bpf_ktime_get_ns() - val->ts;
    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) != 0) {
        char unknown_comm[] = "...";
        __builtin_memcpy(&data.comm, unknown_comm, sizeof(data.comm));
    }
    
    struct vm_fault *vmf = val->vmf;
    data.address = vmf->address;

    struct file *vm_file = vmf->vma->vm_file;
 
    // get device id
    struct vfsmount *mnt = vm_file->f_path.mnt;
    dev_t dev = mnt->mnt_sb->s_dev;
    data.major = MAJOR(dev);
    data.minor = MINOR(dev);
   
    struct dentry *dentry = vm_file->f_path.dentry;

    // get inode
    data.inode = dentry->d_inode->i_ino;
    
    // get filename
    data.type = EVENT_PATH;
    for (int i = 0; ((i < MAXDEPTH) && (dentry != dentry->d_parent)); i++) {
        bpf_probe_read_str(&data.file, sizeof(data.file), dentry->d_name.name);
        events.perf_submit(ctx, &data, sizeof(data));
        dentry = dentry->d_parent;
    }

    faults.delete(&pid);
    data.type = EVENT_RET;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


TASK_COMM_LEN = 16            # linux/sched.h
DNAME_INLINE_LEN = 32         # linux/dcache.h


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("type", ct.c_int),
                ("delta", ct.c_ulonglong),
                ("inode", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("file", ct.c_char * DNAME_INLINE_LEN),
                ("address", ct.c_ulonglong),
                ("major", ct.c_uint),
                ("minor", ct.c_uint)]


class EventType(object):
    EVENT_RET = 0
    EVENT_PATH = 1


class Pagemap(object):
    PFN_MASK = 0x7FFFFFFFFFFFFF
    PAGEMAP = "/proc/{pid}/pagemap"
    KPAGECGROUP = "/proc/kpagecgroup"
    KPAGECOUNT = "/proc/kpagecount"
    CGROUP = "/sys/fs/cgroup/memory"

    @staticmethod
    def _read_pagemap(pagemap, offset, entry_size):
        try:
            with open(pagemap, 'rb') as f:
                f.seek(offset, 0)
                entry = struct.unpack('Q', f.read(entry_size))[0]
        except:
            return
        return entry

    @staticmethod
    def _parse_addr(addr):
        if isinstance(addr, str):
            base = 16 if addr.startswith("0x") else 10
            return int(addr, base=base)
        return addr

    def _get_pfn(self, pid, addr):
        addr = self._parse_addr(addr)
        pagemap = self.PAGEMAP.format(pid=pid)
        if not os.path.isfile(pagemap):
            return
        offset  = (addr / self.page_size) * self.entry_size
        entry = self._read_pagemap(pagemap, int(offset), self.entry_size)
        if not entry:
            return
        return entry & self.PFN_MASK

    def _find_cgroup(self, inode):
        if inode in self.cache_ino:
            return self.cache_ino[inode]
        for root, subdirs, files in os.walk(self.CGROUP):
            if os.stat(root).st_ino == inode:
                self.cache_ino[inode] = root
                return root
        return

    def get_cgroup(self, pid, addr):
        entry = self._get_pfn(pid, addr)
        if not entry:
            return
        offset = entry * self.entry_size
        cgroup_ino = self._read_pagemap(self.KPAGECGROUP, offset, self.entry_size)
        if not cgroup_ino:
            return
        cgroup_name = self._find_cgroup(cgroup_ino)
        if not cgroup_name:
            return cgroup_ino
        return cgroup_name

    def __init__(self):
        self.cache_ino = dict()
        self.page_size = os.sysconf("SC_PAGE_SIZE")
        self.entry_size = 8


class SuppressOutput(list):
    def __enter__(self):
        self._stderr = sys.stderr
        with open(os.devnull, "w") as devnull:
            sys.stderr = devnull
        return self
    def __exit__(self, *args):
        sys.stderr = self._stderr


def process_event(filepaths, event_data, cpu, data, size):
    decode_locale = sys.stdin.encoding or locale.getpreferredencoding(True)

    event = ct.cast(data, ct.POINTER(Data)).contents
    if event.type == EventType.EVENT_PATH:
        key = (event.pid, event.address)

        strfile = event.file.decode(decode_locale)
        if key not in filepaths:
            filepaths[key] = strfile
        else:
            filepaths[key] = os.path.join(strfile, filepaths[key])
    elif event.type == EventType.EVENT_RET:
        key = (event.pid, event.address)
        if key not in filepaths:
            return
        
        # pid
        event_data.pid = event.pid

        # convert ns to ms
        event_data.ts = float(event.delta) / 10**6
        
        # extract byte strings using default locale
        event_data.comm = event.comm.decode(decode_locale)
        
        # represent memory address
        event_data.addr = hex(event.address)
        
        # device id
        event_data.dev = "{}:{}".format(event.major, event.minor)

        # inode
        event_data.inum = event.inode

        # filename
        event_data.filename = filepaths.pop(key)


def get_cgroup_name(pagemap, pid, addr):
    cgroup_name = pagemap.get_cgroup(pid, addr)
    if not cgroup_name:
        cgroup_name = '...'
    elif os.path.isabs(cgroup_name):
        cgroup_name = cgroup_name[len(Pagemap.CGROUP) + 1:]
    return cgroup_name


def poll(b, event, events, pagemap, cgroup):
    while 1:
        b.perf_buffer_poll()
        # cgroup
        if cgroup:
            cgroup_name = get_cgroup_name(pagemap, event.pid, event.addr)
            sub_entity = cgroup_name
        else:
            sub_entity = (event.comm, event.pid)
        if event.filename not in events:
            entity = {
                "counter": 1,
                "sub_entity": Counter({sub_entity})
            }
            events[event.filename] = entity
        else:
            entity = events[event.filename]
            entity["counter"] += 1
            entity["sub_entity"][sub_entity] += 1


def follow_events(b, event, cgroup):
    # header
    header_fmt = "{time:<12} {pid:<12} {comm:<20} {cgroup} {dev:<12} {inum:<12} {file}"

    # cgroup support
    pagemap = Pagemap() if cgroup else None

    print(header_fmt.format(time="TIME(ms)",
                            pid="PID",
                            comm="COMM",
                            dev="DEVICE",
                            inum="INODE",
                            file="FILENAME",
                            cgroup="{:<12}".format("CGROUP") if cgroup else ""))

    # loop with callback to print event
    try:
        while 1:
            b.perf_buffer_poll()

            # cgroup
            cgroup_name = get_cgroup_name(pagemap, event.pid, event.addr) if cgroup else None

            # print eventMAXACTIVE
            print(header_fmt.format(time="{:.4}".format(event.ts),
                                    pid=str(event.pid),
                                    comm=event.comm,
                                    dev=event.dev,
                                    inum=str(event.inum),
                                    file=event.filename,
                                    cgroup="{:<12}".format(cgroup_name) if cgroup else ""))
    except KeyboardInterrupt:
        print("Detaching...")


def format_loadavg():
    with open(loadavg, "r") as stats:
        return "%-8s loadavg: %s" % (time.strftime("%H:%M:%S"), stats.read())


def top(b, event, cgroup, interval, noclear, verbose):
    from threading import Thread
    events = dict()

    # suppress stderr
    if not verbose:
        _stderr, sys.stderr = sys.stderr, open(os.devnull, "w")

    # special chars
    arrow = "─"
    header_arrow = "┌─"
    branch_arrow = "├"
    root_arrow = "└"
    scale_char = "█"
    empty_scale_char = "▒"

    # header
    file_maxlen = 80
    scale_width = 25
    header_fmt = "{{file:<{}}} {{amount}}".format(file_maxlen)

    # cgroup support
    pagemap = Pagemap() if cgroup else None

    t = Thread(target=poll, args=(b, event, events, pagemap, cgroup), daemon=True)
    try:
        print('Tracing... Output every {} secs. Hit Ctrl-C to end'.format(interval))
        t.start()
        while 1:
            time.sleep(interval)
            # update screen
            call("clear") if not noclear else print("")
            print(format_loadavg())
            print(header_fmt.format(file="FILE",
                                    amount="  AMOUNT"))
            for name, options in sorted(events.items(), key=lambda x: x[1]["counter"], reverse=True):
                counter = options["counter"]
                sub_entity = options["sub_entity"]

                print(header_arrow + header_fmt.format(file=name[:file_maxlen],
                                        amount=counter))
                for i, sub_counter in enumerate(sorted(sub_entity.most_common(), key=lambda x: x[1], reverse=True)):
                    sub_name, sub_count = sub_counter
                    if isinstance(sub_name, tuple):
                        sub_name = "{} ({})".format(sub_name[0], sub_name[1])
                    sub_ratio = int(scale_width * sub_count / counter)
                    scale_bar = scale_char * sub_ratio + empty_scale_char * (scale_width - sub_ratio)
                    tree_char = root_arrow if i >= (len(sub_entity) - 1) else branch_arrow
                    print("{tree_char}{arrow}{name:<80}{prc}".format(tree_char=tree_char, arrow=arrow*2, name=sub_name, prc=scale_bar))
            events.clear()
    except KeyboardInterrupt:
        print("Detaching...")
    finally:
        if not verbose:
            sys.stderr.close()
            sys.stderr = _stderr


def main():
    def perf_buffer_lost_cb(lost_cb):
        if args.verbose:
            print("Possibly lost {} samples".format(lost_cb))

    global bpf_text

    args = parse_args()
    
    # pid filter
    if args.pid:
        bpf_text = bpf_text.replace('FILTER',
            'if (pid != {}) {{ return 0; }}'.format(args.pid))
    else:
        bpf_text = bpf_text.replace('FILTER', '')

    # depth replace
    bpf_text = bpf_text.replace('MAXDEPTH', args.max_depth)

    # print bpf text
    if DEBUG or args.ebpf:
        print(bpf_text)
        if args.ebpf:
            return 0

    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event='filemap_fault', fn_name='fault_handle_start')
    b.attach_kretprobe(event='filemap_fault', fn_name='fault_handle_return')

    filepaths = dict()
    event = namedtuple("Event", ["ts", "pid", "addr", "comm", "dev", "inum", "filename", "cgroup"])

    b["events"].open_perf_buffer(
        functools.partial(process_event, filepaths, event), lost_cb=perf_buffer_lost_cb)

    # follow mode
    if args.follow:
        follow_events(b, event, args.cgroup)
    else:
        top(b, event, args.cgroup, args.interval, args.noclear, args.verbose)
    return 0


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace major faults per file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES)
    parser.add_argument("-p", "--pid",
        help="trace specific PID only")
    parser.add_argument("-i", "--interval", type=int, default=1,
        help="output interval (seconds)")
    parser.add_argument("-C", "--noclear", action="store_true", default=False,
        help="do not clear the screen")
    parser.add_argument("--max-depth", default="5",
        help="descend at minimal level in filesystem hierarchy (defaults to 5)")
    parser.add_argument("-f", "--follow", action="store_true", default=False,
        help="trace new events sequently")
    parser.add_argument("-c", "--cgroup", action="store_true", default=False,
        help="show cgroup name which charged faulted memory page")
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    parser.add_argument("--verbose", action="store_true",
        help=argparse.SUPPRESS)
    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
