/* Test cases for various calls

*/

#include <stdio.h>

void inc0() // simple post inc/dec
{
    int i = 14;
    int j = i++;
    int k = i--;
    return;
}

void inc1() // simple pre inc/dec
{
    int i = 14;
    int j = ++i;
    int k = --i;
    return;
}

void inc2() // double pre increments
{
    int i = 14;
    int j = ++i + ++i;
    int k = --i + --i;
    return;
}

void inc3() // double post increments
{
    int i = 14;
    int j = i++ + i++;
    int k = i-- + i--;
    return;
}

int inc4(int i) // increment in the middle of conditional statement
{
    if(i++ < 100)
        return inc4(i);
    return i;
}

int inc5()  // pre-increment that may be switched into a post-increment on the previous statement.
{
    int i = 14;
    int j = i;
    return ++i;
}

int main(int argc, char *argv[])
{
    inc0();
    inc1();
    inc2();
    inc3();
    inc4(0);
    inc5();
}
