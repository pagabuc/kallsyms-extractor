#!/usr/bin/python3

from unicorn_magic import extract_symbols
import tempfile
import struct
import mmap
import sys
import re
import os

THRESHOLD_KSYMTAB  = 2000
THRESHOLD_KALLSYMS = 2000

# Since the ksymtab contains an entry for the function
# kallsyms_on_each_symbol, first of all we find the ksymtab and the
# physical address of "kallsyms_on_each_symbol".

# KASLR randomizes at the page granularity, so page offsets are
# not changed. For this reason, we can search in the symtab all those entries that
# have a name value with the same page offset of the string. At this point
# we know 3 elements of the equation: value_va - name_va =
# value_pa - name_pa and thus we can find value_pa (the physical
# address of the function).

def read_str(dump, address):
    end  = dump[address:address+1024].index(b'\x00')
    return dump[address:address+end].decode('utf-8')

def save_kallsyms(results_dir, ksyms, va, pa):
    filename = os.path.join(results_dir, hex(pa))
    print("[+] Saving %d kallsyms found with kallsyms_on_each_symbol @ 0x%x in %s" % (len(ksyms), va, filename))

    ksyms.sort()

    with open(filename, "w") as f:
        for value, name in ksyms:
            f.write("%016x %s\n" % (value, name))

def extract_kallsyms(dump):
    for ksymtab, va, pa in find_kallsyms_on_each_symbol_function(dump):
        ksyms = extract_symbols(dump, va, pa)
        if len(ksyms) < THRESHOLD_KALLSYMS:
            continue

        # Adding the symbols contained in the ksymtab
        for value, name in ksymtab:
            name_str = read_str(dump, name - va + pa)
            if (value, name_str) not in ksyms:
                ksyms.append((value, name_str))

        yield ksyms, va, pa

# Value can also be a per_cpu pointer, thus the check if is less than 0x100000
def is_valid_entry(value, name):
    return name >= 0xffffffff80000000 and (0xffffffff80000000 <= value < 0xffffffffffffffff or value <= 0x100000)

def find_candidate_ksymtab(dump):
    ksymtab = []
    size = dump.size()
    for i in range(0, size, 16):
        if i % 1000000 == 0:
            sys.stderr.write('\rDone %.2f%%' % ((i)/size*100))

        value, name = struct.unpack("<QQ", dump[i:i+16])
        if is_valid_entry(value, name):
            ksymtab.append((value, name))
            continue

        if len(ksymtab) > THRESHOLD_KSYMTAB:
            yield ksymtab

        ksymtab = []

def find_string(dump, s):
    for match in re.finditer(s, dump):
        yield match.start()

def page_offset(a):
    return a & 0xfff

# Finds those entries in ksymtab that have page_offset(virtual_name) == page_offset(physical_name).
def get_entries_with_name_offset(ksymtab, offsets):
    for (v, n) in ksymtab:
        for o in offsets:
            if page_offset(n) == page_offset(o):
                yield v, n, o

def find_kallsyms_on_each_symbol_function(dump):
    name_pas = list(find_string(dump, b"kallsyms_on_each_symbol\x00"))
    if len(name_pas) == 0:
        print("[-] kallsyms_on_each_symbol string not found, aborting!")
        sys.exit(-1)

    for name_pa in name_pas:
        print("[+] Candidate kallsyms_on_each_symbol string found @ 0x%x" % name_pa)

    for ksymtab in find_candidate_ksymtab(dump):
        print("\n[+] Found a potential ksymtab with: %d elements" % len(ksymtab))
        for value_va, name_va, name_pa in get_entries_with_name_offset(ksymtab, name_pas):
            value_pa = (value_va - name_va) + name_pa
            print("[+] Candidate kallsyms_on_each_symbol function va: 0x%x pa: 0x%x name: 0x%x" % (value_va, value_pa, name_va))
            yield ksymtab, value_va, value_pa

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: %s dump.raw [DUMP MUST BE IN RAW FORMAT]" % sys.argv[0])
        sys.exit(-1)

    with open(sys.argv[1]) as f:
        dump = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    results_dir = tempfile.mkdtemp(prefix="kallsyms_")
    for ksyms, va, pa in extract_kallsyms(dump):
        save_kallsyms(results_dir, ksyms, va, pa)

    print("\n[+] Results saved in: %s" % results_dir)
