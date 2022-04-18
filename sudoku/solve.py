from pwn import *
import json
from sudoku_solver import solve, AdditionalRule


context.log_level = 'debug'
ADDR = '0'
PORT = 9016


def parse_game(p):
    p.recvlines(2)
    board_lines = p.recvlines(9)
    parsed_board_lines = [json.loads(line) for line in board_lines]

    p.recvuntil('should be ')
    op = p.recvuntil(' than ', drop=True)
    size = int(p.recvline())
    curr_loc = p.recv(len('(row, col) :')) # the length of 'solution? : ' is the same
    locs = []
    while b'solution?' not in curr_loc:
        p.recvuntil('(')
        x = int(p.recvuntil(',', drop=True)) - 1
        y = int(p.recvuntil(')', drop=True)) - 1
        locs.append((x, y))
        p.recvline()
        curr_loc = p.recv(len('(row, col) :')) # the length of 'solution? : ' is the same
    return parsed_board_lines, AdditionalRule(locs, size, op.decode())

def main():
    p = remote(ADDR, PORT)
    p.sendline('\n')
    p.recvuntil('press enter to start game\n')
    while True:
        board, rule = parse_game(p)
        solve(board, rule)
        p.sendline(json.dumps(board))
        p.recvuntil('correct!\n')

    p.interactive()


if __name__ == '__main__':
    main()

