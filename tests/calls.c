/* Test cases for various calls

*/

#include <stdio.h>

int call0() // easy one
{
    return 1;
}

void call1() // no return value
{
    return;
}

int call2(int a, int b, int c, int d, 
            int e, int f, int g, int h, int i) // a bunch of arguments (tests argument order and register spill on the stack)
{
    printf("a %u\n", a);
    printf("b %u\n", b);
    printf("c %u\n", c);
    printf("d %u\n", d);
    printf("e %u\n", e);
    printf("f %u\n", f);
    printf("g %u\n", g);
    printf("h %u\n", h);
    printf("i %u\n", i);
    return 1;
}

int call3() // noreturn function call
{
    int *a = 0;
    if(*a == 3)
        _exit(1);
    return 1;
}

int call4() // tail recursion
{
    printf("4\n");
    return fflush(0);
}

int main(int argc, char *argv[])
{
    call0();
    call1();
    call2(0,0,0,0,0,0,0,0,0);
    call3();
    call4();
}
