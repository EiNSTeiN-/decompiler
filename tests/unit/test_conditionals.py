import unittest
import re
import binascii

import test_helper
import decompiler
import ssa

class TestConditionals(test_helper.TestHelper):

  def setUp(self):
    self.functions_x86 = self.objdump_load('../data/conditionals-x86-objdump')
    self.functions_x64 = self.objdump_load('../data/conditionals-x64-objdump')
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if0_x86(self):
    fct = self.functions_x86['if0']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 14) {
          s2 = 134514480;
          -266();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if1_x86(self):
    fct = self.functions_x86['if1']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 != 14) {
          s2 = 134514485;
          -308();
        }
        else {
          s2 = 134514482;
          -308();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if2_x86(self):
    fct = self.functions_x86['if2']

    #dec = self.decompile_until(fct.hex, decompiler.step_stack_propagated)

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 14) {
          s2 = 134514488;
          -364();
        }
        else if (*s0 == 22) {
          s2 = 134514491;
          -364();
        }
        else if (*s0 == 44) {
          s2 = 134514494;
          -364();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if3_x86(self):
    fct = self.functions_x86['if3']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 || *s0 == 4) {
          s2 = 134514497;
          -454();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if4_x86(self):
    fct = self.functions_x86['if4']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 && *s0 == 4) {
          s2 = 134514499;
          -506();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if5_x86(self):
    fct = self.functions_x86['if5']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0 = 0;
        if (*s0 == 3 || s0 && *s0 == 4) {
          s2 = 134514501;
          -558();
        }
        return 0;
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if6_x86(self):
    fct = self.functions_x86['if6']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0@91 = 0;
        if (*s0@91@84 >= 399) {
          eax@81 = 1;
        }
        else if (*s0@91@84 >= 500) {
          eax@80 = 2;
        }
        else if (*s0@91@84 > 600) {
          eax@79 = 3;
        }
        else if (*s0@91@84 > 699) {
          eax@78 = 4;
        }
        else if (*s0@91@84 <= 800) {
          eax@61 = 5;
        }
        else {
          eax@77 = 0;
        }
        return THETA(eax@61, eax@77, eax@78, eax@79, eax@80, eax@81, );
      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if7_x86(self):
    fct = self.functions_x86['if7']

    self.assert_step(decompiler.step_decompiled, fct.hex,
      """
      func() {
        s0@91 = 0;
        if (*s0@91@84 <= 399) {
          eax@81 = 1;
        }
        else if (*s0@91@84 <= 500) {
          eax@80 = 2;
        }
        else if (*s0@91@84 > 600) {
          eax@79 = 3;
        }
        else if (*s0@91@84 > 699) {
          eax@78 = 4;
        }
        else if (*s0@91@84 >= 800) {
          eax@61 = 5;
        }
        else {
          eax@77 = 0;
        }
        return THETA(eax@61, eax@77, eax@78, eax@79, eax@80, eax@81, );
      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
