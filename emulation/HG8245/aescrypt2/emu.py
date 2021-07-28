#!/usr/bin/env python
from qiling import Qiling
from unicorn import *
from unicorn.arm64_const import *
from qiling.const import QL_VERBOSE
from qiling.const import QL_INTERCEPT
from qiling.os.posix.syscall.stat import pack_stat64_struct
import sys
import os


def ql_syscall__llseek(
    ql, fd, offset_high, offset_low, result, whence, *args, **kw
):

    #  _llseek negative seek bug fix
    offset_high = int.from_bytes(
        offset_high.to_bytes(ql.pointersize, "little"), "little", signed=True
    )
    offset_low = int.from_bytes(
        offset_low.to_bytes(ql.pointersize, "little"), "little", signed=True
    )

    offset = offset_high << 32 | offset_low
    origin = whence
    regreturn = 0
    try:
        ret = ql.os.fd[fd].lseek(offset, origin)
    except OSError:
        regreturn = -1
    if regreturn == 0:
        ql.mem.write(result, ql.pack64(ret))
    ql.log.debug(
        "_llseek(%d, 0x%x, 0x%x, 0x%x) = %d"
        % (fd, offset_high, offset_low, origin, regreturn)
    )
    return regreturn


def ql_syscall_readv(ql, fd, vec, vlen, *args, **kw):
    regreturn = 0
    size_t_len = ql.pointersize
    iov = ql.mem.read(vec, vlen * size_t_len * 2)
    ql.log.debug("readv() CONTENT:")

    for i in range(vlen):
        addr = ql.unpack(
            iov[i * size_t_len * 2 : i * size_t_len * 2 + size_t_len]
        )
        l = ql.unpack(
            iov[
                i * size_t_len * 2
                + size_t_len : i * size_t_len * 2
                + size_t_len * 2
            ]
        )
        regreturn += l
        if hasattr(ql.os.fd[fd], "read"):
            data = ql.os.fd[fd].read(l)
            ql.log.debug(data)
            ql.mem.write(addr, data)

    return regreturn


def ql_syscall_clock_gettime(ql, clockid_t, kernel_timespec, *args, **kw):
    return 0


def ql_syscall_rename(ql, oldname_buf, newname_buf, *args, **kw):
    """
    rename(const char *oldpath, const char *newpath)
    description: change the name or location of a file
    ret value: On success, zero is returned. On error, -1 is returned
    """
    regreturn = 0  # default value is success
    oldpath = ql.mem.string(oldname_buf)
    newpath = ql.mem.string(newname_buf)

    ql.log.debug(f"rename() path: {oldpath} -> {newpath}")

    old_realpath = ql.os.path.transform_to_real_path(oldpath)
    new_realpath = ql.os.path.transform_to_real_path(newpath)

    if old_realpath == new_realpath:
        # do nothing, just return success
        return regreturn

    try:
        os.rename(old_realpath, new_realpath)
        regreturn = 0
    except OSError:
        ql.log.exception(f"rename(): {newpath} is exist!")
        regreturn = -1

    return regreturn


def prepare() -> Qiling:
    #
    # decrypt var_ctree
    # var_pack_temp_dir=/bin/
    # var_default_ctree=/mnt/jffs2/customize_xml/hw_default_ctree.xml
    # var_temp_ctree=/mnt/jffs2/customize_xml/hw_default_ctree_tem.xml
    # $var_pack_temp_dir/aescrypt2 1 $var_default_ctree $var_temp_ctree

    cur_dir = os.path.abspath(".")
    ql = Qiling(
        [
            cur_dir + "/rootfs/bin/aescrypt2",
            "1",  # decrypt flag for encryption set to 0
            "/mnt/jffs2/hw_ctree.xml",  # encrypted file
            # i couldnt understand what second arg's purpose because
            # aescrypt2 renames this field to original file
            # it is like a dummy file imo.
            "/tmp/hw_ctree.gz",
        ],
        cur_dir + "/rootfs/",
        verbose=QL_VERBOSE.DEBUG,
        console=True,
    )
    return ql


def main():
    ql = prepare()

    ql.root = True  # not really needed
    # ql.debugger = "qdb"
    ql.add_fs_mapper("/proc", "/proc")
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.add_fs_mapper("/dev/random", "/dev/random")

    ql.set_syscall(145, ql_syscall_readv)
    ql.set_syscall(140, ql_syscall__llseek)
    ql.set_syscall(263, ql_syscall_clock_gettime)
    ql.set_syscall(38, ql_syscall_rename)

    #ql.filter = r"^open"
    ql.run()


if __name__ == "__main__":
    main()
