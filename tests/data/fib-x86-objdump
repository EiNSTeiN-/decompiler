0804848c <main>:
 804848c: 55                    push   %ebp
 804848d: 89 e5                 mov    %esp,%ebp
 804848f: 83 e4 f0              and    $0xfffffff0,%esp
 8048492: 83 ec 20              sub    $0x20,%esp
 8048495: c7 44 24 18 00 00 00  movl   $0x0,0x18(%esp)
 804849c: 00
 804849d: 8d 44 24 14           lea    0x14(%esp),%eax
 80484a1: 89 44 24 04           mov    %eax,0x4(%esp)
 80484a5: c7 04 24 e8 85 04 08  movl   $0x80485e8,(%esp)
 80484ac: e8 df fe ff ff        call   8048390 <__isoc99_scanf@plt>
 80484b1: c7 04 24 eb 85 04 08  movl   $0x80485eb,(%esp)
 80484b8: e8 a3 fe ff ff        call   8048360 <puts@plt>
 80484bd: c7 44 24 1c 01 00 00  movl   $0x1,0x1c(%esp)
 80484c4: 00
 80484c5: eb 26                 jmp    80484ed <main+0x61>
 80484c7: 8b 44 24 18           mov    0x18(%esp),%eax
 80484cb: 89 04 24              mov    %eax,(%esp)
 80484ce: e8 2b 00 00 00        call   80484fe <Fibonacci>
 80484d3: 89 44 24 04           mov    %eax,0x4(%esp)
 80484d7: c7 04 24 fc 85 04 08  movl   $0x80485fc,(%esp)
 80484de: e8 6d fe ff ff        call   8048350 <printf@plt>
 80484e3: 83 44 24 18 01        addl   $0x1,0x18(%esp)
 80484e8: 83 44 24 1c 01        addl   $0x1,0x1c(%esp)
 80484ed: 8b 44 24 14           mov    0x14(%esp),%eax
 80484f1: 39 44 24 1c           cmp    %eax,0x1c(%esp)
 80484f5: 7e d0                 jle    80484c7 <main+0x3b>
 80484f7: b8 00 00 00 00        mov    $0x0,%eax
 80484fc: c9                    leave
 80484fd: c3                    ret

080484fe <Fibonacci>:
 80484fe: 55                    push   %ebp
 80484ff: 89 e5                 mov    %esp,%ebp
 8048501: 53                    push   %ebx
 8048502: 83 ec 14              sub    $0x14,%esp
 8048505: 83 7d 08 00           cmpl   $0x0,0x8(%ebp)
 8048509: 75 07                 jne    8048512 <Fibonacci+0x14>
 804850b: b8 00 00 00 00        mov    $0x0,%eax
 8048510: eb 2d                 jmp    804853f <Fibonacci+0x41>
 8048512: 83 7d 08 01           cmpl   $0x1,0x8(%ebp)
 8048516: 75 07                 jne    804851f <Fibonacci+0x21>
 8048518: b8 01 00 00 00        mov    $0x1,%eax
 804851d: eb 20                 jmp    804853f <Fibonacci+0x41>
 804851f: 8b 45 08              mov    0x8(%ebp),%eax
 8048522: 83 e8 01              sub    $0x1,%eax
 8048525: 89 04 24              mov    %eax,(%esp)
 8048528: e8 d1 ff ff ff        call   80484fe <Fibonacci>
 804852d: 89 c3                 mov    %eax,%ebx
 804852f: 8b 45 08              mov    0x8(%ebp),%eax
 8048532: 83 e8 02              sub    $0x2,%eax
 8048535: 89 04 24              mov    %eax,(%esp)
 8048538: e8 c1 ff ff ff        call   80484fe <Fibonacci>
 804853d: 01 d8                 add    %ebx,%eax
 804853f: 83 c4 14              add    $0x14,%esp
 8048542: 5b                    pop    %ebx
 8048543: 5d                    pop    %ebp
 8048544: c3                    ret
 8048545: 66 90                 xchg   %ax,%ax
 8048547: 66 90                 xchg   %ax,%ax
 8048549: 66 90                 xchg   %ax,%ax
 804854b: 66 90                 xchg   %ax,%ax
 804854d: 66 90                 xchg   %ax,%ax
 804854f: 90                    nop
