#!/usr/bin/env python

from capstone import *
from typing import Optional, Tuple
import sys
import argparse
from qiling import *
from pwn import *


# good informations in this file
# https://github.com/avast/retdec/blob/master/src/capstone2llvmirtool/capstone2llvmir.cpp

last_register = None
only_main = False

def hook_callback(ql, address, size):
    global last_register
    global only_main
    # read current instruction bytes
    data = ql.mem.read(address, size)
    # initialize Capstone
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
    # disassemble current instruction
    for i in md.disasm(data, address):
        addr = f"0x{i.address:08x}"
        if only_main:
            if int(addr,16) > 0x00400b80 and int(addr,16) < 0x004012ac:
                last_register = [hex(ql.reg.arch_pc), hex(ql.reg.arch_sp), hex(ql.reg.get_uc_reg("ra"))]
                print("[*] 0x{:08x}: {} {}".format(i.address, i.mnemonic, i.op_str))
        else:
                last_register = [hex(ql.reg.arch_pc), hex(ql.reg.arch_sp), hex(ql.reg.get_uc_reg("ra"))]
                print("[*] 0x{:08x}: {} {}".format(i.address, i.mnemonic, i.op_str))


def parser() -> Optional[Tuple[str, bool, bool]]:
    global only_main
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="chosen AFL input file", type=str)
    try:
        parser.add_argument(
            "--verbose", help="be verbose about process", dest="verbose", action="store_true"
        )
    except TypeError:
        pass
    try:
        parser.add_argument("--hook", help="enable disasm output", dest="hook", action="store_true")
    except TypeError:
        pass

    try:
        parser.add_argument("--main", help="show only main flow", dest="main", action="store_true")
    except TypeError:
        pass
    args = parser.parse_args()
    only_main = args.main

    if args.input is None:
        print("[ERR] Please, how should I know the name of input file?")
        sys.exit()

    return args.input, args.verbose, args.hook


def read_file(filename: str) -> bytes:
    file = open(filename, "rb")
    content = file.read()
    return content


def main(input_content: bytes, enable_trace: bool, hook: bool):
    env_vars = {
        "REQUEST_METHOD": "GET",
        "REQUEST_URI": "/cgi-bin/login",
        "CONTENT-TYPE": "application/x-www-form-urlencoded",
        "REMOTE_ADDR": "0.0.0.0",
        "REMOTE_PORT": "80",
        "QUERY_STRING": "user=echel0n&password=ILOVEQILING&redirect=" + "A"*370,  # fill here
    }
    ql = Qiling(
        ["/home/qiling_projects/Airties/5650v3TT/squashfs-root/webs/cgi-bin/login"],
        rootfs="/home/qiling_projects/Airties/5650v3TT/squashfs-root/",
        output="default",
        env=env_vars,
        console=True if enable_trace else False,
    )

    if hook:
        main_addr = ql.os.elf_entry
        ql.hook_code(hook_callback)
    try:
        ql.run()
    except:
        print("[*] Process exited but something happened.")
        print("[*] Last Registers:")
        print(f"[*] $pc : {hex(ql.reg.arch_pc)}")
        print(f"[*] $sp : {hex(ql.reg.arch_sp)}")
        print("[*] $sp:data ")
        print(ql.mem.read(ql.reg.arch_sp,16))
        sys.exit()


if __name__ == "__main__":
    input_file, verbose, hook = parser()
    input_content = read_file(input_file)

    main(input_content, verbose, hook)
