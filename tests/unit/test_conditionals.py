# coding=utf-8

import unittest
import re
import binascii

from test_helper import *
import decompiler
import ssa

class TestConditionals(TestHelper):

  def setUp(self):
    TestHelper.setUp(self)
    self.functions_x86 = self.objdump_load('../data/conditionals-x86-objdump')
    self.functions_x86_64 = self.objdump_load('../data/conditionals-x64-objdump')
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if0_x86(self):
    fct = self.functions_x86['if0']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 14) {
          -266(134514480);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if1_x86(self):
    fct = self.functions_x86['if1']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 != 14) {
          -308(134514485);
        }
        else {
          -308(134514482);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if2_x86(self):
    fct = self.functions_x86['if2']

    #dec = self.decompile_until(fct.hex, decompiler.step_stack_propagated)

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 14) {
          -364(134514488);
        }
        else if (*s0 == 22) {
          -364(134514491);
        }
        else if (*s0 == 44) {
          -364(134514494);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if3_x86(self):
    fct = self.functions_x86['if3']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 || *s0 == 4) {
          -454(134514497);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if4_x86(self):
    fct = self.functions_x86['if4']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 && *s0 == 4) {
          -506(134514499);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if5_x86(self):
    fct = self.functions_x86['if5']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 || s0 && *s0 == 4) {
          -558(134514501);
        }
        return 0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if6_x86(self):
    fct = self.functions_x86['if6']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 >= 399) {
          v0 = 1;
        }
        else if (*s0 >= 500) {
          v0 = 2;
        }
        else if (*s0 > 600) {
          v0 = 3;
        }
        else if (*s0 > 699) {
          v0 = 4;
        }
        else if (*s0 <= 800) {
          v0 = 5;
        }
        else {
          v0 = 0;
        }
        return v0;
      }
      """)
    return

  @callconv('cdecl')
  @disasm('capstone-x86')
  def test_if7_x86(self):
    fct = self.functions_x86['if7']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 <= 399) {
          v0 = 1;
        }
        else if (*s0 <= 500) {
          v0 = 2;
        }
        else if (*s0 > 600) {
          v0 = 3;
        }
        else if (*s0 > 699) {
          v0 = 4;
        }
        else if (*s0 >= 800) {
          v0 = 5;
        }
        else {
          v0 = 0;
        }
        return v0;
      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
