# coding=utf-8

import unittest
import re
import binascii

from test_helper import *
import decompiler
import ssa

class TestLoops(TestHelper):

  def setUp(self):
    TestHelper.setUp(self)
    self.functions_x86 = self.objdump_load('../data/loops-x86-objdump')
    #self.functions_x86_64 = self.objdump_load('../data/loops-x64-objdump')
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop0_x86(self):
    fct = self.functions_x86['loop0']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = a0;
        while (1) {
          s1 = s1 + 1;
          -307(134515040, s1);
        }
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop1_x86(self):
    fct = self.functions_x86['loop1']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 29) {
          -339(134515040, s0);
          s0 = s0 + 1;
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_loop2_x86(self):
    fct = self.functions_x86['loop2']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        while (s0 <= 9) {
          s0 = s0 + 1;
          -391(134515040, s0);
        }
        return 0;
      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
