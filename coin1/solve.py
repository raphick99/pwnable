from pwn import *


context.log_level = 'debug'
host = 'pwnable.kr'
port = 9007


def get_info(p):
    p.recvuntil('N=')
    coins = int(p.recvuntil(' ')[:-1])
    p.recvuntil('C=')
    chances = int(p.recvuntil('\n')[:-1])
    return coins, chances


def run_loop(p, coins, chances):
    while len(coins) > 1:
        split_index = len(coins) / 2

        p.sendline(' '.join(coins[:split_index]))
        weight = int(p.recvline())
        if weight % 10 != 0:
            coins = coins[:split_index]
        else:
            coins = coins[split_index:]
    p.sendline(coins[0])
    return coins[0]


def main():
    p = remote(host, port)
    print(p.recvuntil('sec... -\n'))

    while True:
        coins, chances = get_info(p)
        coins = [str(i) for i in range(0, coins)]
        counterfeit = run_loop(p, coins, chances)
        end_res = p.recvline()
        if '9' in end_res and 'Correct!' not in end_res:  # for some reason, sometimes it didnt realize that i was sending the result, and still sent me the weight back
            p.sendline(counterfeit)
            end_res = p.recvline()
        if 'Correct!' not in end_res:  # this would occure on error or flag
            p.interactive()


if __name__ == '__main__':
    main()

