#!/usr/bin/env python3

from collections import namedtuple
from typing import NamedTuple
from pprint import pprint
import argparse
import itertools
import sys

SeekResult = namedtuple('SeekResult', ['data', 'address', 'region', 'perm', 'pid'])


class MemoryRegion(NamedTuple):
    name: str
    start: int
    end: int
    perm: str
    size: int
    pid: int

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
    def __init__(self, pid, region_filter=None):
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

                    # cumulative search of all filter items in a simple serialization of "info" dict
                    lookup_str = ''.join(map(str, region._asdict().values()))
                    if not region_filter or all(lookup_str.find(f_itm) >= 0 for f_itm in region_filter):
                        self.regions.append(region)
                        total_size += region.size

                self.total_size_kib = total_size // 1024

        except FileNotFoundError:
            raise Exception(f"PID '{self.pid}' not found!")

    def __write(self, address, data):
        try:
            with open(f"/proc/{self.pid}/mem", "r+b") as mem_file:
                mem_file.seek(address)
                mem_file.write(bytes(data.replace("\\x00", "\x00"), "ASCII"))
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
                    yield SeekResult(read_data, seek, region.name, region.perm, self.pid)
                    break
            else:
                while True:
                    mem = region.read()
                    offset = mem.find(seek.encode(), last_addr)
                    if offset < 0:
                        break

                    absolute_addr = region.start + offset
                    if write:
                        self.__write(absolute_addr, write)

                    read_data = region.read_at_address(offset, nb_bytes=read)
                    last_addr = offset + 1
                    yield SeekResult(read_data, hex(absolute_addr), region.name, region.perm, self.pid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='simple process memory toolset')

    # Global options
    parser.add_argument('pids', nargs='+', type=int, help='The pid to operate on')
    parser.add_argument('-f', '--filter', nargs='+', help='Filter on memory by region name or address')
    parser.add_argument('-d', '--dump', default=False, action="store_true", help='Dump memory into stdout')

    # Seek options
    parser.add_argument('-s', '--seek', help='Pattern to seek in memory, or address if prefixed with "0x"')
    parser.add_argument('-w', '--write', nargs='?', help='String to write at position found by the "--seek" argument')
    parser.add_argument('-b', '--read-bytes', nargs='?', type=int, help='Number of bytes to read when seeking a pattern')

    args = parser.parse_args()

    processes = map(lambda pid: ProcessMemory(pid, args.filter), args.pids)

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
            pprint(results)

    else:
        all_regions = [region for process in processes for region in process.regions]
        for reg in all_regions:
            pprint(reg._asdict())
