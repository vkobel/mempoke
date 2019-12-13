#!/usr/bin/env python3
from collections import namedtuple
from hashlib import md5
import sys
import argparse
import time
import itertools

from process_vm import ProcessVmWritev

SeekResult = namedtuple('SeekResult', ['term', 'data', 'address', 'region'])
pvmw = ProcessVmWritev()


class MemoryRegion:
    name: str
    start: int
    end: int
    perm: str
    size: int
    pid: int
    __checksum: str

    def __init__(self, name, start, end, perm, size, pid):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm
        self.size = size
        self.pid = pid
        self.__checksum = None

    def find(self, pattern):
        with open(f"/proc/{self.pid}/mem", "rb") as mm:
            try:
                mm.seek(self.start)
                mm = mm.read(self.size)
                last_pos = 0
                while True:
                    offset = mm.find(to_bytes(pattern), last_pos)
                    if offset < 0:
                        break
                    last_pos = offset + 1
                    yield self.start + offset

            except (OSError, ValueError):
                print(f"Ignoring {self.name}...")

    def checksum(self):
        if not self.__checksum:
            self.__checksum = digest(self.read_region())
        return self.__checksum

    def read_at(self, address, nb_bytes=None):
        if address < self.start or address >= self.end:
            raise ValueError('address not part of memory region')

        with open(f"/proc/{self.pid}/mem", "rb") as mm:
            if nb_bytes and type(nb_bytes) == int:
                # if read-bytes flag is used, read that amount of bytes before and after
                mm.seek(address - nb_bytes)
                return mm.read(nb_bytes * 2)
            else:
                # read until next zero byte or at max 50
                mm.seek(address)
                try:
                    mem = mm.read(50)
                    until_zero = mem.find(b'\x00')
                    return mem[:until_zero] if until_zero >= 0 else mem
                except OSError:
                    return None

    def write_at(self, address, write_bytes):
        pvmw.write_vm(self.pid, address, to_bytes(write_bytes))


class ProcessMemory:
    def __init__(self, pid, incl_filter=None, excl_filter=None):
        self.pid = pid
        self.regions = []

        total_size = 0
        try:
            with open(f"/proc/{pid}/maps", "r") as maps_file:
                for line in maps_file:
                    region_info = line.split()
                    addrs = list(map(lambda x: int(x, 16), region_info[0].split("-")))

                    region = MemoryRegion(
                        name=region_info[5] if len(region_info) > 5 else "ANONYMOUS",
                        start=addrs[0],
                        end=addrs[1],
                        perm=region_info[1],
                        size=addrs[1] - addrs[0],
                        pid=self.pid
                    )

                    lookup_str = ''.join(map(str, [region.name, region.start, region.perm, region.size, region.pid]))

                    if (not incl_filter and not excl_filter) or \
                       (not incl_filter or any(lookup_str.find(f_itm) >= 0 for f_itm in incl_filter)) and \
                       (not excl_filter or all(lookup_str.find(f_itm) < 0 for f_itm in excl_filter)):

                        self.regions.append(region)
                        total_size += region.size

                self.total_size_kib = total_size // 1024

        except FileNotFoundError:
            print(f"PID '{self.pid}' cannot be found")
            quit(1)

    def find_bytes(self, seek, write=None, read=None):
        for region in self.regions:

            # if seeking an address (starting with '0x'), just go directly there without looping
            if seek[:2] == '0x':
                dec_addr = int(seek, 16)
                if region.start <= dec_addr and region.end > dec_addr:
                    if write:
                        region.write_at(dec_addr, write)
                    read_data = region.read_at(dec_addr, nb_bytes=read)
                    yield SeekResult(seek, read_data, seek, region)
                    break
            else:
                for addr in region.find(seek):
                    if write:
                        region.write_at(addr, write)
                    read_data = region.read_at(addr, read)
                    yield SeekResult(seek, read_data, hex(addr), region)


def to_bytes(data):
    if data.isdecimal():
        integer = int(data)
        # bytes repr as of : https://docs.python.org/3/library/stdtypes.html#int.to_bytes
        return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder=sys.byteorder)
    else:
        return data.replace("\\x00", "\x00").encode()


def from_bytes(data):
    if not data.isascii():
        return int.from_bytes(data, byteorder=sys.byteorder)
    else:
        return data


def digest(data):
    h = md5()
    h.update(data)
    return h.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='simple process memory toolset')

    # Global options
    parser.add_argument('pids', nargs='+', type=int, help='The pid to operate on')
    parser.add_argument('-i', '--include', nargs='+', help='Filter on memory region name or address to include')
    parser.add_argument('-e', '--exclude', nargs='+', help='Filter on memory region name or address to exclude')
    parser.add_argument('-d', '--dump', default=False, action="store_true", help='Dump memory into stdout')
    parser.add_argument('-c', '--checksum', default=False, action="store_true", help='Provide md5 checksum for memory region')

    # Seek options
    parser.add_argument('-s', '--seek', help='Pattern to seek in memory, or address if prefixed with "0x"')
    parser.add_argument('-w', '--write', nargs='?', help='Data to write at position found by the "--seek" argument')
    parser.add_argument('-b', '--read-bytes', nargs='?', type=int, help='Number of bytes to read when seeking a pattern')

    parser.add_argument('-a', '--active', choices=['freq', 'syscall'], help='Enters "active" mode, you must supply a seek pattern. Write is also supported.')
    parser.add_argument('-f', '--freq', nargs='?', type=int, default=50, help='Frequency of active "freq" mode, in milliseconds, defaults to 50ms')

    args = parser.parse_args()

    if args.dump:
        processes = map(lambda pid: ProcessMemory(pid, incl_filter=args.include, excl_filter=args.exclude), args.pids)
        all_regions = [region for process in processes for region in process.regions]
        for region in all_regions:
            sys.stdout.buffer.write(region.read_region())

        if len(all_regions) > 1:
            sys.stderr.buffer.write(b"\n\nWarning multiple memory regions have been dump")

    elif args.seek:
        if args.active == 'freq':
            mon_dict = {}
            i = 0
            while True:

                # Find way to make monitor more efficient
                # Here we re instantiate all matching process everytime -> not efficient?
                # Make use of force refresh cache flag if necessary
                # For example, re read only if memory region has changed (check checksum)

                try:
                    processes = map(lambda pid: ProcessMemory(pid, incl_filter=args.include, excl_filter=args.exclude), args.pids)
                    results = itertools.chain.from_iterable(map(lambda p: p.find_bytes(args.seek, write=args.write, read=args.read_bytes), processes))
                    for res in results:
                        if res.address not in mon_dict.keys() or mon_dict[res.address] != res.data:
                            mon_dict[res.address] = res.data
                            print(f"{i}:", f"[{res.region.pid}]", res.data, "@", res.address, "in", res.region.name)

                    i += 1
                    time.sleep(args.freq / 1000)
                except KeyboardInterrupt:
                    print()
                    print(mon_dict)
                    quit(0)

        else:
            processes = map(lambda pid: ProcessMemory(pid, incl_filter=args.include, excl_filter=args.exclude), args.pids)
            results = itertools.chain.from_iterable(map(lambda p: p.find_bytes(args.seek, write=args.write, read=args.read_bytes), processes))
            for res in results:
                print("term:", res.term)
                print(" ", "data:", res.data)
                print(" ", "found at:", res.address)
                print(" ", "pid:", res.region.pid)
                print(" ", "region:", res.region.name)
                print()

    else:
        # General region information
        processes = map(lambda pid: ProcessMemory(pid, incl_filter=args.include, excl_filter=args.exclude), args.pids)
        all_regions = [region for process in processes for region in process.regions]
        for reg in all_regions:
            print(f"[{reg.pid}] region:", reg.name)
            print(" ", "address:", hex(reg.start), "-", hex(reg.end))
            print(" ", "size:", reg.size)
            print(" ", "perm:", reg.perm)
            if args.checksum:
                print(" ", "checksum:", reg.checksum())
            print()
