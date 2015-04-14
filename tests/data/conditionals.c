/* Test cases for various 'if' constructs

*/

#include <stdio.h>

int main(int argc, char *argv[])
{
    if0();
    if1();
    if2();
    if3();
    if4();
    if5();
}

int if0() // basic if
{
    int *a = 0;
    if(*a == 14) {
        printf("0\n");
    }
    return 0;
}

int if1() // basic if-else
{
    int *a = 0;
    if(*a == 14) {
        printf("11\n");
    } else {
        printf("12\n");
    }
    return 0;
}

int if2() // if with else-if
{
    int *a = 0;
    if(*a == 14) {
        printf("21\n");
    } else if(*a == 22) {
        printf("22\n");
    } else if(*a == 44) {
        printf("23\n");
    }
    return 0;
}

int if3() // multiple conditions
{
    int *a = 0;
    if(*a == 3 || *a == 4) {
        printf("3\n");
    }
    return 0;
}

int if4() // multiple conditions
{
    int *a = 0;
    if(*a == 3 && *a == 4) {
        printf("4\n");
    }
    return 0;
}

int if5() // multiple conditions
{
    int *a = 0;
    if(*a == 3 || (a && *a == 4)) {
        printf("5\n");
    }
    return 0;
}

int if6() // signed inequalities
{
    int *a = 0;
    
    if(*a < 400)
        return 1;

    if(*a <= 500)
        return 2;

    if(*a > 600)
        return 3;

    if(*a >= 700)
        return 4;

    if(*a > 800 || *a == 800)
        return 5;

    return 0;
}

int if7() // unsigned inequalities
{
    unsigned int *a = 0;
    
    if(*a < 400)
        return 1;

    if(*a <= 500)
        return 2;

    if(*a > 600)
        return 3;

    if(*a >= 700)
        return 4;

    if(*a > 800 || *a == 800)
        return 5;

    return 0;
}
