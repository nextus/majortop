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

from bcc import BPF

EXAMPLES = """examples:
    ./majortop           # trace all major faults
    ./majortop -p 181    # only trace PID 181
    ./majortop -f        # follow mode
"""
DEBUG = 0


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
                ("minor", ct.c_uint),
                ("cg", ct.c_char * 32)]


class EventType(object):
    EVENT_RET = 0
    EVENT_PATH = 1


# process event
def print_event(filepaths, cpu, data, size):
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
        
        # convert ns to ms
        delta_ms = float(event.delta) / 10**6
        # extract byte strings using default locale
        strcomm = event.comm.decode(decode_locale)
        # represent memory address
        hexaddress = hex(event.address)
        # device id
        strdevice = "{}:{}".format(event.major, event.minor)

        # print
        print("%-12.4f %-12d %-20s %-12d %-16s %-9s %s" % (delta_ms, event.pid, strcomm,
                                                      event.inode, hexaddress,
                                                      strdevice, filepaths[key]))

        filepaths.pop(key, None)


def main():
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

    # header
    print("%-12s %-12s %-20s %-12s %-16s %-9s %s" % ("TIME(ms)", "PID", "COMM",
                                                "INODE", "ADDRESS", "DEVICE", "FILENAME"))

    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event='filemap_fault', fn_name='fault_handle_start')
    b.attach_kretprobe(event='filemap_fault', fn_name='fault_handle_return')

    filepaths = dict()

    # follow mode
    if args.follow:
        # loop with callback to print event
        b["events"].open_perf_buffer(
            functools.partial(print_event, filepaths))
        try:
            while 1:
                b.perf_buffer_poll()
        except KeyboardInterrupt:
            pass
        return 0
    

def parse_args():
    parser = argparse.ArgumentParser(
        description="Trace major faults per file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EXAMPLES)
    parser.add_argument("-p", "--pid",
        help="trace specific PID only")
    parser.add_argument("--max-depth", default="5",
        help="descend at minimal level in filesystem hierarchy (defaults to 5)")
    parser.add_argument("-f", "--follow", action="store_true", default=True,
        help="trace new events sequently")
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
