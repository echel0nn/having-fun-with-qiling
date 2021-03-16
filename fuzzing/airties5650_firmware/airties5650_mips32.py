#!/usr/bin/env python

import os, sys
import unicornafl

unicornafl.monkeypatch()
sys.path.append("../../../")
from qiling import *

def main(input_file, enable_trace=False):
    env_vars = {
        "REQUEST_METHOD": "GET",
        "REQUEST_URI": "/cgi-bin/login",
        "CONTENT-TYPE": "application/x-www-form-urlencoded",
        "REMOTE_ADDR": "0.0.0.0",
        "REMOTE_PORT": "1881",
        "QUERY_STRING": "user=echel0n&password=ILOVEQILING&redirect=" + "A" * 0x1000 # fill here
    }

    ql = Qiling(["/home/qiling_projects/Airties/5650v3TT/squashfs-root/webs/cgi-bin/login"],
                 "/home/qiling_projects/Airties/5650v3TT/squashfs-root/", output="debug", env=env_vars,
                console = True if enable_trace else False)

    def place_input_callback(uc, input, _, data):
        env_var = ("user=echel0n&password=ILOVEQILING&redirect=").encode()
        env_vars = env_var + input + b"\x00" + (ql.path).encode() + b"\x00"
        ql.mem.write(ql.target_addr, env_vars)

    def start_afl(_ql: Qiling):
        try:
            print("Starting afl_fuzz().")
            if not _ql.uc.afl_fuzz(input_file=input_file,
                                   place_input_callback=place_input_callback,
                                   exits=[ql.os.exit_point]):
                print("Ran once without AFL attached.")
                os._exit(0)
        except unicornafl.UcAflError as ex:

            if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
                raise

    addr = ql.mem.search("QUERY_STRING=user=echel0n&password=ILOVEQILING&redirect=".encode())
    ql.target_addr = addr[0]
    main_addr = ql.os.elf_entry
    ql.hook_address(callback=start_afl, address=main_addr)
    try:
        ql.run()
        os._exit(0)
    except:
        if enable_trace:
            print("went broke, get help")
        os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        raise ValueError("No input file provided.")
    if len(sys.argv) > 2 and sys.argv[1] == "-t":
        main(sys.argv[2], enable_trace=True)
    else:
        main(sys.argv[1])
