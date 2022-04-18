#include <stdio.h>
#include <stdint.h>

void test_sizet(int a)
{
    printf("is a larger then 0: %d\n", a > 0);
}

int
main()
{
    int a = 0;
    scanf("%d", &a);
    test_sizet(a);
    return 0;
}
