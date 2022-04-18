from pwn import *
import argh
import random


context.log_level = 'info'
bin_path = './memcpy'
e = ELF(bin_path)


ADDR = 'pwnable.kr'
PORT = 9022


gdbscript = '''
layout regs
continue
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], gdbscript=gdbscript)


def set_experiment(p, index):
    low = 2 ** (index-1)
    high = 2 ** index
    p.recvuntil('{} ~ {} : '.format(low, high))
    random_in_range = random.randint(low, high)
    log.info('chosen in {} ~ {} : {}'.format(low, high, random_in_range))
    p.sendline(str(random_in_range))


@argh.arg('--local', '-l', help='Run locally')
@argh.arg('--debug', '-d', help='Run with gdb')
@argh.arg('--runpwn', '-r', help='Run remotely')
def main(local=False, debug=False, runpwn=False):
    p = None

    if local:
        p = process(bin_path)
    elif debug:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)
    else:
        log.critical('no run instruction given!!')
        log.critical('shutting down...')
        return

    for i in range(4, 14):
        set_experiment(p, i)

    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

