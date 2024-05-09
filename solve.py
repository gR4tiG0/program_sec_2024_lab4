#!/usr/bin/env python3
from pwn import *
import logging

logging.basicConfig(level=logging.DEBUG)

logging.getLogger("pwnlib").setLevel(logging.WARNING)

ORG_FILENAME = "./Crack_me_up!.exe"
OUT_FILENAME = "./patched.exe"
JZ_SEQ = b'\x0f\x84\x25\x01\x00\x00'

LAUNCH_COND_SEQ_JBE = b'\x76\x17\x6a\x00\x68\xc8\xd2\x40\x00'
LAUNCH_COND_SEQ_JNZ = b'\x75\x17\x6a\x01\x68\x8c\xd2\x40\x00'

CHECK_NAME_SEQ_JNZ = b'\x0f\x85\xdb\x00\x00\x00'


context.arch = 'i386'

def transformName(username:str) -> int:
    username = username.encode()
    strlen_username = len(username)
    output = 0xfacc0fff
    for counter in range(strlen_username):
        output = ((username[counter] ^ output) << 8) | (output >> 0x18)
        output = output & 0xffffffff
    return output

def getPass(name_transformed:int) -> str:
    password = ''
    for _ in range(8):
        low_byte = name_transformed & 0xf
        if 9 < low_byte:
            low_byte = 9
        password += str(low_byte)
        name_transformed = name_transformed >> 4
    return password




def getPatch(name_bypass:bool = False, login_bypass:bool = False) -> None:
    with open(ORG_FILENAME, 'rb') as f:
        file = f.read()

    patched_bin = file

    if login_bypass:
        logging.info(f"Applying login bypass patch")
        logging.debug(f"Login bypass disasm:")
        logging.debug(disasm(JZ_SEQ))
        patched_seq = JZ_SEQ[:1] + b'\x85' + JZ_SEQ[2:]
        logging.debug(disasm(patched_seq))    

        j_offset = file.find(JZ_SEQ)

        patched_bin = file[:j_offset] + patched_seq + file[j_offset+len(patched_seq):]

    cond_jbe = file.find(LAUNCH_COND_SEQ_JBE)
    cond_jnz = file.find(LAUNCH_COND_SEQ_JNZ)

    logging.debug(f"Launch conditions disasm:")
    logging.debug(disasm(LAUNCH_COND_SEQ_JBE[:2]))
    logging.debug(disasm(LAUNCH_COND_SEQ_JNZ[:2]))

    patched_seq_jbe = b'\xeb' + LAUNCH_COND_SEQ_JBE[1:2]
    patched_seq_jnz = b'\xeb' + LAUNCH_COND_SEQ_JNZ[1:2]
    logging.debug(f"Patch disasm:")
    logging.debug(disasm(patched_seq_jbe))
    logging.debug(disasm(patched_seq_jnz))
    
    jbe_offset = file.find(LAUNCH_COND_SEQ_JBE)
    jnz_offset = file.find(LAUNCH_COND_SEQ_JNZ)

    patched_bin = patched_bin[:jbe_offset] + patched_seq_jbe + patched_bin[jbe_offset+len(patched_seq_jbe):]
    patched_bin = patched_bin[:jnz_offset] + patched_seq_jnz + patched_bin[jnz_offset+len(patched_seq_jnz):]

    if name_bypass:
        logging.info(f"Applying name bypass patch")
        logging.debug(f"Check 'noname' disasm:")
        logging.debug(disasm(CHECK_NAME_SEQ_JNZ))

        check_name_offset = file.find(CHECK_NAME_SEQ_JNZ)
        patched_seq_check_name = b'\x90' * len(CHECK_NAME_SEQ_JNZ)
        logging.debug(f"Patch disasm:")
        logging.debug("\n" + disasm(patched_seq_check_name))

        patched_bin = patched_bin[:check_name_offset] + patched_seq_check_name + patched_bin[check_name_offset+len(patched_seq_check_name):]


    assert len(patched_bin) == len(file)
    with open(OUT_FILENAME, 'wb') as f:
        f.write(patched_bin)

def main() -> None:
    getPatch(True)

    name = "gratigo"
    logging.info(f"Username: {name}")
    name_trasnformed = transformName(name)
    passwd = getPass(name_trasnformed)
    logging.info(f"Password: {passwd}")


if __name__ == "__main__":
    main()
