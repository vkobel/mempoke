import ctypes.util


class Syscall:
    def __init__(self, func, argtypes=None, restype=ctypes.c_int8):
        LIBC_NAME = ctypes.util.find_library('c')
        LIBC = ctypes.CDLL(LIBC_NAME)

        self.fn = getattr(LIBC, func)
        self.fn.restype = restype
        self.fn.argtypes = argtypes

    def __call__(self, *args):
        return self.fn(*args)


class ProcessVmReadv(Syscall):
    class iovec(ctypes.Structure):
        _fields_ = (
            ('iov_base', ctypes.c_void_p),
            ('iov_len', ctypes.c_size_t)
        )

    def __init__(self):
        super().__init__('process_vm_readv', restype=ctypes.c_long,
                         argtypes=[ctypes.c_int,
                                   ctypes.POINTER(self.iovec),
                                   ctypes.c_ulong,
                                   ctypes.POINTER(self.iovec),
                                   ctypes.c_ulong,
                                   ctypes.c_ulong])

    def read_vm(self, pid, address, len_fwd=None, len_prev=0):
        # if nothing is set, read 50 bytes
        if not len_fwd:
            len_fwd = 50

        bytes_to_read = len_prev + len_fwd

        buf = ctypes.create_string_buffer(bytes_to_read)
        lmem = self.iovec()
        lmem.iov_base = ctypes.cast(ctypes.byref(buf), ctypes.c_void_p)
        lmem.iov_len = bytes_to_read

        rmem = self.iovec()
        rmem.iov_base = address - len_prev
        rmem.iov_len = bytes_to_read

        nread = self(pid, lmem, 1, rmem, 1, 0)
        if nread != bytes_to_read:
            raise Exception(f"Issue reading memory! Bytes read: {nread} instead of {bytes_to_read}")
        else:
            return buf.raw


class ProcessVmWritev(Syscall):
    class iovec(ctypes.Structure):
        _fields_ = (
            ('iov_base', ctypes.c_void_p),
            ('iov_len', ctypes.c_size_t)
        )

    def __init__(self):
        super().__init__('process_vm_writev', restype=ctypes.c_long,
                         argtypes=[ctypes.c_int,
                                   ctypes.POINTER(self.iovec),
                                   ctypes.c_ulong,
                                   ctypes.POINTER(self.iovec),
                                   ctypes.c_ulong,
                                   ctypes.c_ulong])

    def write_vm(self, pid, address, bytes_to_write):
        write_len = len(bytes_to_write)

        buf = ctypes.create_string_buffer(bytes_to_write)
        lmem = self.iovec()
        lmem.iov_base = ctypes.cast(ctypes.byref(buf), ctypes.c_void_p)
        lmem.iov_len = write_len

        rmem = self.iovec()
        rmem.iov_base = address
        rmem.iov_len = write_len

        nwrite = self(pid, lmem, 1, rmem, 1, 0)
        if nwrite != write_len:
            raise Exception(f"Issue writing memory! Bytes written: {nwrite} instead of {bytes_to_write}")
        else:
            return nwrite
