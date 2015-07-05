# coding=utf-8

import unittest
import re
import binascii

from test_helper import *
import decompiler
import ssa

class TestFibonacci(TestHelper):

  def setUp(self):
    TestHelper.setUp(self)
    self.functions_x86 = self.objdump_load('../data/fib-x86-objdump')
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_main_x86(self):
    fct = self.functions_x86['main']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        s2 = &s1 - 4 & -16 - 12;
        -252(134514152, s2);
        -300(134514155, s2);
        s4 = 1;
        while (s4 <= s5) {
          s2 = 114(s0, s2);
          -316(134514172, s2);
          s0 = s0 + 1;
          s4 = s4 + 1;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_Fibonacci_x86(self):
    fct = self.functions_x86['Fibonacci']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func(a0) {
        if (!a0) {
          v0 = 0;
        }
        else if (a0 != 1) {
          v0 = 0(a0 - 2) + 0(a0 - 1);
        }
        else {
          v0 = 1;
        }
        return v0;
      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
