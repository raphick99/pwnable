from pwn import *
import hashlib


context.log_level = 'info'


ADDR = 'pwnable.kr'
PORT = 9006


def encryption_oracle(s):
    client = remote(ADDR, PORT)

    client.recvuntil('Input your ID\n')
    client.sendline(s)
    client.recvuntil('Input your PW\n')
    client.sendline('')
    client.recvuntil('data (')
    encrypted = client.recvuntil(')', drop=True)
    client.close()

    return unhex(encrypted)


def attack(blocksize, known):
    index = len(known) // blocksize
    prefix = 'a'*(blocksize-len(known)%blocksize-1)
    lookup = {}

    full_enc = encryption_oracle(prefix)
    substring = full_enc[index*blocksize:index*blocksize+blocksize]
    for char in '_-abcdefghijklmnopqrstuvwxyz1234567890':
        curr = encryption_oracle(prefix+known+char)
        curr = curr[index*blocksize:index*blocksize+blocksize]
        if curr == substring:
            return char
        if curr in lookup.keys():
            log.critical('curr is already in keys. preexisting: {}, new: {}'.format(lookup[curr], char))
            continue
        lookup[curr] = char

    return None


def bruteforce_cookie():
    plain = 'you_will_never_guess_this_sugar_honey_salt_cookie'
    while True:
        curr = attack(16, plain)
        if curr == None:
            break
        plain += curr
        log.critical('Found plaintext:\n{}'.format(plain))

    print('done [{}]'.format(plain))


def main():
    cookie = 'you_will_never_guess_this_sugar_honey_salt_cookie'
    client = remote(ADDR, PORT)

    client.recvuntil('Input your ID\n')
    client.sendline('admin')
    client.recvuntil('Input your PW\n')
    client.sendline(hashlib.sha256('admin' + cookie).hexdigest())
    client.recvuntil('here is your flag\n')
    print(client.recvline())


if __name__ == '__main__':
    main()

