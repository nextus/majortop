#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# majortop Trace major pagefaults with related filenames.
#          For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: majortop [-h] [-f]
#
# It's initial release without aggregation feature.

import sys
import locale
import argparse
from bcc import BPF
import ctypes as ct


EXAMPLES = """examples:
    ./majortop           # trace all major faults
    ./majortop -p 181    # only trace PID 181
    ./majortop -f        # follow mode
"""
DEBUG = 0


# define BPF program
bpf_text = """
#include <linux/mm.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 delta;
    u64 inode;
    char comm[TASK_COMM_LEN];
    char file[DNAME_INLINE_LEN];
    u64 address;
};

struct val_t {
    struct vm_area_struct *vma;
    u64 ts;
    u64 address;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(faults, u32, struct val_t);

int fault_handle_start(struct pt_regs *ctx, struct vm_area_struct *vma, u64 address) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    struct val_t val = {};
    val.vma = vma;
    val.ts = bpf_ktime_get_ns();
    val.address = address;
    
    faults.update(&pid, &val);

    return 0;
}

int fault_handle_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER

    vm_fault_t fault = PT_REGS_RC(ctx);

    struct val_t *val = faults.lookup(&pid);
    if (val == 0)
        return 0;
 
    if ( !(fault & VM_FAULT_MAJOR)) {
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
    data.address = val->address;

    struct file *vm_file = val->vma->vm_file;
    if (vm_file == 0) {
        data.inode = 0;
        char anon_file[] = "[ anon ]";
        __builtin_memcpy(&data.file, anon_file, sizeof(data.file));
    } else {
        // get filename
        struct dentry *dentry = vm_file->f_path.dentry;
        struct qstr d_name = dentry->d_name;
        bpf_probe_read_str(&data.file, sizeof(data.file), d_name.name);
           
        // get inode
        data.inode = dentry->d_inode->i_ino;
    }

    faults.delete(&pid);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


TASK_COMM_LEN = 16            # linux/sched.h
DNAME_INLINE_LEN = 32         # linux/dcache.h


class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("delta", ct.c_ulonglong),
                ("inode", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("file", ct.c_char * DNAME_INLINE_LEN),
                ("address", ct.c_ulonglong)]


# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    # convert ns to ms
    delta_ms = float(event.delta) / 10**6
    # extract byte strings using default locale
    decode_locale = sys.stdin.encoding or locale.getpreferredencoding(True)
    strcomm = event.comm.decode(decode_locale)
    strfile = event.file.decode(decode_locale)

    # represent memory address
    hexaddress = hex(event.address)

    # print
    print("%-12.4f %-12d %-20s %-12d %-16s %s" % (delta_ms, event.pid, strcomm,
                                            event.inode, hexaddress, strfile))


def main():
    global bpf_text

    args = parse_args()
    
    # pid filter
    if args.pid:
        bpf_text = bpf_text.replace('FILTER',
            'if (pid != {}) {{ return 0; }}'.format(args.pid))
    else:
        bpf_text = bpf_text.replace('FILTER', '')

    # print bpf text
    if DEBUG or args.ebpf:
        print(bpf_text)
        if args.ebpf:
            return 0

    # header
    print("%-12s %-12s %-20s %-12s %-16s %s" % ("TIME(ms)", "PID", "COMM",
                                                "INODE", "ADDRESS", "FILENAME"))

    # initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event='handle_mm_fault', fn_name='fault_handle_start')
    b.attach_kretprobe(event='handle_mm_fault', fn_name='fault_handle_return')

    # follow mode
    if args.follow:
        # loop with callback to print event
        b["events"].open_perf_buffer(print_event)
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
    parser.add_argument("-f", "--follow", action="store_true", default=True,
        help="trace new events sequently")
    parser.add_argument("--ebpf", action="store_true",
        help=argparse.SUPPRESS)
    return parser.parse_args()


if __name__ == '__main__':
    sys.exit(main())
