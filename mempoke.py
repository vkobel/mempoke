#!/usr/bin/env python3

from pprint import pprint
import argparse
import sys


def get_memory_info(pids, filter=None):
    ret = []
    for pid in pids:
        try:
            with open(f"/proc/{pid}/maps", "r") as maps_file:
                for line in maps_file:
                    region_info = line.split()
                    addrs = region_info[0].split("-")
                    perm = region_info[1]
                    region = region_info[5] if len(region_info) > 5 else addrs[0]

                    info = {"region": region,
                            "start": addrs[0],
                            "end": addrs[1],
                            "perm": perm,
                            "size": int(addrs[1], 16) - int(addrs[0], 16),
                            "pid": pid}

                    # cumulative search of all filter items in a simple serialization of "info" dict
                    lookup_str = ''.join(map(str, info.values()))
                    if not filter or all(lookup_str.find(f_itm) >= 0 for f_itm in filter):
                        ret.append(info)

        except FileNotFoundError:
            print("PID not found!")
            quit(1)

    return ret


def get_memory_data(mem_info):
    ret = []
    for region in mem_info:
        with open(f"/proc/{region['pid']}/mem", "r+b") as mem_file:
            mem_file.seek(int(region["start"], 16))
            try:
                mem = mem_file.read(region["size"])
                ret.append(mem)
            except OSError:
                ret.append(bytes())
    return ret


def seek_memory(mem_info, mem_data, pattern, replace=None, read=None):
    results = []
    for inf, mem in zip(mem_info, mem_data):
        last_addr = 0
        while True:
            offset = mem.find(pattern.encode(), last_addr)
            if offset < 0:
                break
            found_addr = int(inf["start"], 16) + offset
            if read and type(read) == int:
                # if read-bytes flag is used, read that amount of bytes
                results.append({'read': mem[offset:offset + read], 'addr': hex(found_addr), 'region': inf["region"]})
            else:
                # By default, read until next zero byte or at max 150
                until_zero = mem.find(b'\x00', offset)
                if until_zero - offset > 150:
                    until_zero = offset + 150
                results.append({'read': mem[offset:until_zero], 'addr': hex(found_addr), 'region': inf["region"]})
            last_addr = offset + 1

            if replace:
                with open(f"/proc/{inf['pid']}/mem", "r+b") as mem_file:
                    mem_file.seek(found_addr)
                    mem_file.write(bytes(replace + '\0', "ASCII"))
                    mem_file.flush()

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='simple process memory toolset')

    # Global options
    parser.add_argument('pids', nargs='+', type=int, help='The pid to operate on')
    parser.add_argument('-f', '--filter', nargs='+', help='Filter on memory by region name or address')
    parser.add_argument('-d', '--dump', default=False, action="store_true", help='Dump memory into stdout')

    # Seek options
    parser.add_argument('-s', '--seek', help='Pattern to seek in memory')
    parser.add_argument('-w', '--write', nargs='?', help='String to write at position found by the "--seek" argument')
    parser.add_argument('-b', '--read-bytes', nargs='?', type=int, help='Number of bytes to read when seeking a pattern')

    args = parser.parse_args()

    if args.dump:
        mem_info = get_memory_info(args.pids, args.filter)
        mem_data = get_memory_data(mem_info)
        for mem in mem_data:
            sys.stdout.buffer.write(mem)

        if len(mem_info) > 1:
            sys.stderr.buffer.write(b"\n\nWarning multiple memory regions have been dump")

    elif args.seek:
        mem_info = get_memory_info(args.pids, args.filter)
        mem_data = get_memory_data(mem_info)
        if not args.seek:
            print('argument "-p/--pattern" is required by the "seek" operation!')
            quit(1)

        results = seek_memory(mem_info, mem_data, args.seek, replace=args.write, read=args.read_bytes)
        if not results:
            print("pattern not found")
            quit(1)
        else:
            pprint(results)

    else:
        pprint(get_memory_info(args.pids, args.filter))
