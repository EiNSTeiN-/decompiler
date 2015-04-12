import unittest
import re
import binascii

import test_helper
import decompiler
import ssa

class TestDecompile(test_helper.TestHelper):

  def setUp(self):
    self.functions = self.objdump_load('../data/conditionals-x86-objdump')
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def test_if0(self):
    fct = self.functions['if0']

    self.assert_step(decompiler.step_propagated, fct.hex,
      """
      func() {

      }
      """)
    return

  @test_helper.TestHelper.disasm_capstone_x86
  def if1(self):
    fct = self.functions['if1']

    self.assert_step(decompiler.step_propagated, fct.hex,
      """
      func() {

      }
      """)
    return

if __name__ == '__main__':
  unittest.main()
