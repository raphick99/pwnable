#include <stdlib.h>
#include <time.h>
#include <stdio.h>

int
main(int argc, char* argv[])
{
    if (3 != argc)
    {
        puts("usage: get_canary <seed> <captcha>");
        return 1;
    }

    int seed = strtol(argv[1], NULL, 0);
    int captcha = strtol(argv[2], NULL, 0);

    srand(seed);
    int buf[8] = {0};

    for (int i = 0; i < 8; i++)
    {
        buf[i] = rand();
        // printf("0x%x\n", buf[i]);
    }
    int res = buf[4] - buf[6] + buf[7] + buf[2] - buf[3] + buf[5] + buf[1] - captcha;
    res *= -1;
    printf("0x%x\n", res);
    

    return 0;
}
