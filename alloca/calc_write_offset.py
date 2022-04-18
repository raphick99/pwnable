from pwn import *


def calc_buffer(curr_esp, size):
    size += 34
    size /= 0x10
    size *= 0x10

    curr_esp -= size
    returned_stack = curr_esp + 0xf
    returned_stack >>= 4
    returned_stack <<= 4
    return curr_esp, returned_stack


def get_distance_from_target(target, esp, size):
    new_esp, buf = calc_buffer(esp, size)
    canary_loc = buf + size
    return canary_loc - target

