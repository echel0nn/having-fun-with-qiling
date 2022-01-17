#!/usr/bin/env python
import random

CALL_ADD = b"\x42"
CALL_SUB = b"\x26"
CALL_XOR = b"\x40"
PASSWORD = open("password", "wb")


def echelon_num_machine(call_num, reg_1, reg_2):

    if reg_1 > 0xFF or reg_2 > 0xFF:
        return -1
    if call_num == CALL_ADD:
        return reg_1 + reg_2
    elif call_num == CALL_SUB:
        return reg_1 - reg_2
    elif call_num == CALL_XOR:
        return reg_1 ^ reg_2


def random_call_chooser():
    call_list = [CALL_ADD, CALL_SUB, CALL_XOR]
    return random.choice(call_list)


def echelonvm_to_humaneyes(call_n, reg_1, reg_2):
    call_n = call_n.to_bytes(1, "little")
    if reg_1 > 0xFF or reg_2 > 0xFF:
        return -1
    if call_n == CALL_ADD:
        return f"ADD {reg_1} {reg_2}"
    elif call_n == CALL_SUB:
        return f"SUB {reg_1} {reg_2}"
    elif call_n == CALL_XOR:
        return f"XOR {reg_1} {reg_2}"


def echelon_num_machine_revert(call_num, reg_1, reg_2):
    call_num = call_num.to_bytes(1, "little")
    if reg_1 > 0xFF or reg_2 > 0xFF:
        return -1
    if call_num == CALL_ADD:
        return reg_1 - reg_2
    elif call_num == CALL_SUB:
        return reg_1 + reg_2
    elif call_num == CALL_XOR:
        return reg_1 ^ reg_2


def echelonvm_solver():
    stack = []
    echelonvm_f = open("./echelonvm_code", "rb")
    content = echelonvm_f.read()
    real_password = ""
    # call, reg_1, reg_2
    for i in range(0, len(content), 3):
        call = content[i]
        reg_1 = content[i + 1]
        reg_2 = content[i + 2]
        output = echelon_num_machine_revert(call, reg_1, reg_2)
        print(
            echelonvm_to_humaneyes(int(call), int(reg_1), int(reg_2)),
            f" = {output}",
        )
        real_password += chr(output)

    print(f"Password is: {real_password}")

def to_echelonvm():
    real_password = "itaintmuchbuthonestworkdontyouthink!"
    ECHELONVM_F = open("echelonvm_code", "wb")

    for char in real_password:
        reg_1 = char
        reg_2 = random.randint(0, ord(char))
        call = random_call_chooser()
        output = echelon_num_machine(call, ord(reg_1), reg_2)
        # CALL, REG_1, REG_2
        ECHELONVM_F.write(call)
        ECHELONVM_F.write((output).to_bytes(1, "little"))
        ECHELONVM_F.write((reg_2).to_bytes(1, "little"))
        PASSWORD.write((output).to_bytes(1, "little"))
    ECHELONVM_F.close()


def main():
    # to_echelonvm()
    echelonvm_solver()


if __name__ == "__main__":
    main()
