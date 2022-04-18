from pwn import *
import argh


bin_path = './ascii'
e = ELF(bin_path)


host = 'pwnable.kr'
user = 'ascii'
port = 2222
password = 'guest'


gdbscript = '''
layout regs
continue
'''


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--debug', '-d', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, debug=False, runpwn=False):
    p = None

    if local:
        p = process(bin_path)
    elif debug:
        p = gdb.debug(bin_path, gdbscript=gdbscript)
    elif runpwn:
        s = ssh(user, host, port, password)
        p = s.process(argv)
    else:
        log.critical('no run instruction given!!')
        log.critical('shutting down...')
        return

    p.sendline(cyclic(length=1024))
    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

