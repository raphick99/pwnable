from pwn import *


# context.log_level = 'info'
host = 'pwnable.kr'
port = 9008


def get_info(p):
    p.recvuntil('N=')
    coins = int(p.recvuntil(' ')[:-1])
    p.recvuntil('C=')
    chances = int(p.recvuntil('\n')[:-1])
    return coins, chances


def build_payload(coins, chances):
    buckets = []
    for i in range(chances):
        block_size = 2**i
        curr_bucket = []
        # import ipdb; ipdb.set_trace()
        for j in range(0, coins, block_size):
            if (j / block_size) % 2 == 1:
                continue
            curr_bucket.extend(str(k) for k in range(j, j + block_size) if k < coins)

        buckets.append(curr_bucket)
    return buckets, '-'.join(' '.join(l) for l in buckets)


def run_loop(p, coins, chances):
    buckets, payload = build_payload(coins, chances)
    p.sendline(payload)
    weights = [int(w) for w in p.recvline().decode().split('-')]
    bad_buckets = []
    not_it = []

    for weight, bucket in zip(weights, buckets):
        if weight % 10 != 0:
            bad_buckets.append(set(bucket))
        else:
            not_it.extend(bucket)

    options = list(set.intersection(*bad_buckets))
    for coin in not_it:
        if coin in options:
            options.remove(coin)

    if len(options) != 1:
        raise RuntimeError(f'failed to find the coin: {len(options)}, {options}')
    p.sendline(options[0])
    return options[0]


def main():
    p = remote(host, port)
    p.recvuntil('sec ... -\n')
    p.recvline()

    while True:
        coins, chances = get_info(p)
        counterfeit = run_loop(p, coins, chances)
        end_res = p.recvline()
        # if '9' in end_res and 'Correct!' not in end_res:  # for some reason, sometimes it didnt realize that i was sending the result, and still sent me the weight back
        #    p.sendline(counterfeit)
        #    end_res = p.recvline()
        if b'Correct!' not in end_res:  # this would occure on error or flag
            p.interactive()


if __name__ == '__main__':
    main()

