/* Test cases for loops

*/

#include <stdio.h>

int main(int argc, char *argv[])
{
    loop0();
    loop1();
    loop2();
    loop3();
    loop4();
    loop5();
    loop6();
    loop7();
    loop8();
    loop9();
    loop10();
}

int loop0() // a while loop with no stop condition.
{
    int i;
    while(1) {
        printf("%u\n", i++);
    }
    return 0;
}

int loop1() // your standard for-loop
{
    int i;
    for(i=0;i<30;i++) {
        printf("%u\n", i);
    }
    return 0;
}

int loop2() // your standard while-loop
{
    int i=0;
    while(i<10) {
        printf("%u\n", i++);
    }
    return 0;
}

int loop3() // your standard do-while
{
    int i=0;
    do {
        printf("%u\n", i++);
    } while(i<10);
    return 0;
}

int loop4() // a for-loop with 'continue'
{
    int i;
    for(i=0;i<30;i++) {
        if(i == 4) {
            printf("four\n");
        }
        else if(i == 12) {
            continue;
        }
        printf("%u\n", i);
    }
    return 0;
}

int loop5() // a while-loop with 'continue'
{
    int i=0;
    while(i++ != 10) {
        if(i == 5) {
            printf("five\n");
        }
        else if(i == 12) {
            continue;
        }
        printf("%u\n", i);
    }
    return 0;
}

int loop6() // a do-while-loop with 'continue'
{
    int i=0;
    do {
        if(i == 6) {
            printf("six\n");
            continue;
        }
        printf("%u\n", i);
    } while(i++ < 10);
    return 0;
}

int loop7() // a for-loop with 'break'
{
    int i;
    for(i=0;i<30;i++) {
        if(i == 7) {
            printf("seven\n");
            break;
        }
        printf("%u\n", i);
    }
    return 0;
}

int loop8() // a while-loop with 'break'
{
    int i=0;
    while(i++ < 10) {
        if(i == 8) {
            printf("eight\n");
            break;
        }
        printf("%u\n", i);
    }
    return 0;
}

int loop9() // a do-while-loop with 'break'
{
    int i=0;
    do {
        if(i == 9) {
            printf("nine\n");
            break;
        }
        printf("%u\n", i);
    } while(i++ < 10);
    return 0;
}

int loop10() // a for-loop with 'continue' which cannot be inverted with the tailing statement of the for-loop.
{
    int *a;
    int i;
    for(i=0;i<30;i++) {
        if(i == 4) {
            printf("four\n");
        }
        else if(i == 12) {
            *a = 18;
            continue;
        }
        else if(i == 6) {
            *a = 10;
            continue;
        }
        printf("%u\n", i);
    }
    return 0;
}

int loop11() // nested loops
{
    int i,j;
    for(j=0;j<30;j++) {
        for(i=0;i<30;i++) {
            printf("%u%u\n", i, j);
        }
        for(i=0;i<30;i++) {
            printf("%u%u\n", i, j);
        }
    }
    return 0;
}

int loop12() // nested loops
{
    int i,j;
    for(j=0;j<30;j++) {
        for(i=0;i<30;i++) {
            if(i == 8) {
                printf("8\n");
                break;
            }
            printf("%u%u\n", i, j);
        }
        printf("%u\n", j);
    }
    return 0;
}

int loop13() // nested loops
{
    int i,j;
    for(j=0;j<30;j++) {
        do {
            printf("%u\n", i++);
        } while(i<10);
        printf("%u\n", j);
    }
    return 0;
}
