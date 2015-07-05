# coding=utf-8

import unittest

import test_helper
import decompiler
import ssa

class TestStack(test_helper.TestHelper):

  def test_simple_register(self):

    input = """
      esp = 1;
      return esp;
    """

    expected = """
    func() {
      return 1;
    }
    """

    self.assert_step(decompiler.step_stack_propagated, input, expected)
    return

  def test_phi_simple(self):

    input = """
          if(a > 1) goto 200;
    100:  esp = 1;
          goto 300;
    200:  esp = 2;
    300:  return esp;
    """

    expected = """
    func() {
      goto loc_3 if(a@0 > 1) else goto loc_1;
    loc_1:
      esp@3 = 1;
      goto loc_4;
    loc_3:
      esp@1 = 2;
      goto loc_4;
    loc_4:
      esp@2 = Φ(esp@3, esp@1, );
      return esp@2;
    }
    """

    self.assert_step(decompiler.step_stack_propagated, input, expected)
    return

  def test_phi_if_else(self):

    input = """
          *(esp) = 1;
          esp = esp + 4;
          if(a > 1) goto 200;
    100:  *(esp) = 1;
          goto 300;
    200:  *(esp) = 2;
    300:  return 1;
    """

    expected = """
    func() {
      *(esp@0) = 1;
      goto loc_5 if(a@2 > 1) else goto loc_3;
    loc_3:
      *(esp@0 + 4) = 1;
      goto loc_6;
    loc_5:
      *(esp@0 + 4) = 2;
      goto loc_6;
    loc_6:
      return 1;
    }
    """

    self.assert_step(decompiler.step_stack_propagated, input, expected)
    return

  def test_propagate_stack_pushes(self):

    input = """
      *(esp) = 1;
      esp = esp - 4;
      *(esp) = 2;
      esp = esp - 4;
      *(esp) = 3;
      esp = esp + 8;
      return eax;
    """

    self.assert_step(decompiler.step_stack_propagated, input, """
    func() {
      *(esp@0) = 1;
      *(esp@0 - 4) = 2;
      *(esp@0 - 8) = 3;
      esp@3 = esp@0;
      return eax@4;
    }
    """)

    self.assert_step(decompiler.step_stack_renamed, input, """
    func() {
      s0@8 = 1;
      s1@9 = 2;
      s2@10 = 3;
      return;
    }
    """)
    return

  def test_stack_address_rename(self):

    input = """
      *(esp) = 1;
      esp = esp + 4;
      eax = esp - 4;
      esp = esp - 4;
      return eax;
    """

    self.assert_step(decompiler.step_stack_propagated, input, """
    func() {
      *(esp@0) = 1;
      esp@3 = esp@0;
      return esp@0;
    }
    """)

    self.assert_step(decompiler.step_stack_pruned, input, """
    func() {
      s0@5 = 1;
      return &s0@5;
    }
    """)
    return

  def test_same_stack_address_get_same_name(self):

    input = """
      *(esp - 4) = 1;
      *(esp - 4) = 2;
      return *(esp - 4);
    """

    self.assert_step(decompiler.step_stack_propagated, input, """
    func() {
      *(esp@0 - 4) = 1;
      *(esp@0 - 4) = 2;
      return *(esp@0 - 4);
    }
    """)

    self.assert_step(decompiler.step_stack_renamed, input, """
    func() {
      s0@3 = 1;
      s0@4 = 2;
      return s0@4;
    }
    """)
    return

if __name__ == '__main__':
  unittest.main()
