#!/usr/bin/env python3

from collections import namedtuple
from pprint import pprint
from hashlib import md5
import sys
import argparse
import itertools

SeekResult = namedtuple('SeekResult', ['term', 'data', 'address', 'region'])


def digest(data):
    h = md5()
    h.update(data)
    return h.hexdigest()


class MemoryRegion:
    name: str
    start: int
    end: int
    perm: str
    size: int
    pid: int
    checksum: str

    def __init__(self, name, start, end, perm, size, pid):
        self.name = name
        self.start = start
        self.end = end
        self.perm = perm
        self.size = size
        self.pid = pid

    def read(self):
        with open(f"/proc/{self.pid}/mem", "r+b") as mem_file:
            mem_file.seek(self.start)
            try:
                return mem_file.read(self.size)
            except OSError:
                return bytes()

    def read_at_address(self, rel_address, nb_bytes=None):
        mem_data = self.read()

        if nb_bytes and type(nb_bytes) == int:
            # if read-bytes flag is used, read that amount of bytes
            return mem_data[rel_address - nb_bytes:rel_address + nb_bytes]
        else:
            # read until next zero byte or at max 150
            until_zero = mem_data.find(b'\x00', rel_address)
            if until_zero - rel_address > 150:
                until_zero = rel_address + 150
            return mem_data[rel_address:until_zero]


class ProcessMemory:
    def __init__(self, pid, incl_filter=None, excl_filter=None, checksum=False):
        self.pid = pid
        self.regions = []

        total_size = 0
        try:
            with open(f"/proc/{pid}/maps", "r") as maps_file:
                for line in maps_file:
                    region_info = line.split()
                    addrs = list(map(lambda x: int(x, 16), region_info[0].split("-")))

                    region = MemoryRegion(
                        name=region_info[5] if len(region_info) > 5 else hex(addrs[0]),
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

                        if checksum:
                            region.checksum = digest(region.read())

                        self.regions.append(region)
                        total_size += region.size

                self.total_size_kib = total_size // 1024

        except FileNotFoundError:
            raise Exception(f"PID '{self.pid}' not found!")

    def __write(self, address, data):
        try:
            with open(f"/proc/{self.pid}/mem", "r+b") as mem_file:
                mem_file.seek(address)
                # mem_file.write(bytes(data.replace("\\x00", "\x00"), "ASCII"))
                mem_file.write(to_bytes(data))
                mem_file.flush()
        except OSError:
            pass

    def seek_memory(self, seek, write=None, read=None):
        for region in self.regions:
            last_addr = 0

            # if seeking an address (starting with '0x'), just go directly there without looping
            if seek[:2] == '0x':
                dec_addr = int(seek, 16)
                if region.start <= dec_addr and region.end > dec_addr:

                    if write:
                        self.__write(dec_addr, write)

                    read_data = region.read_at_address(dec_addr - region.start, nb_bytes=read)
                    yield SeekResult(seek, read_data, seek, region)
                    break
            else:
                mem = region.read()
                while True:
                    term = to_bytes(seek)
                    offset = mem.find(term, last_addr)
                    if offset < 0:
                        break

                    absolute_addr = region.start + offset
                    if write:
                        self.__write(absolute_addr, write)

                    read_data = region.read_at_address(offset, nb_bytes=read)
                    last_addr = offset + 1
                    yield SeekResult(term, read_data, hex(absolute_addr), region)


def to_bytes(data):
    if data.isdecimal():
        integer = int(data)
        # bytes repr as of : https://docs.python.org/3/library/stdtypes.html#int.to_bytes
        return integer.to_bytes((integer.bit_length() + 7) // 8, byteorder=sys.byteorder)
    else:
        return data.encode()


def from_bytes(data):
    if not data.isascii():
        return int.from_bytes(data, byteorder=sys.byteorder)
    else:
        return data


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
    parser.add_argument('-w', '--write', nargs='?', help='String to write at position found by the "--seek" argument')
    parser.add_argument('-b', '--read-bytes', nargs='?', type=int, help='Number of bytes to read when seeking a pattern')

    parser.add_argument('-m', '--monitor', default=False, action="store_true", help='Enters monitoring mode')

    args = parser.parse_args()

    processes = map(lambda pid: ProcessMemory(pid, incl_filter=args.include, excl_filter=args.exclude, checksum=args.checksum), args.pids)

    if args.dump:
        all_regions = [region for process in processes for region in process.regions]
        for region in all_regions:
            sys.stdout.buffer.write(region.read())

        if len(all_regions) > 1:
            sys.stderr.buffer.write(b"\n\nWarning multiple memory regions have been dump")

    elif args.seek:
        results = list(itertools.chain.from_iterable(map(lambda p: list(p.seek_memory(args.seek, write=args.write, read=args.read_bytes)), processes)))
        if not results:
            print("pattern not found")
            quit(1)
        else:
            for res in results:
                print("Term: ", res.term)
                print("Data: ", res.data)
                print("Address: ", res.address)
                pprint(vars(res.region))
                print()

    else:
        all_regions = [region for process in processes for region in process.regions]
        for reg in all_regions:
            pprint(vars(reg))
