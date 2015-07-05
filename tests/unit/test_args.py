# coding=utf-8

import unittest

import test_helper
import decompiler
import ssa

class TestArgs(test_helper.TestHelper):

  def test_simple_register_argument(self):

    input = """
      eax = edx;
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@2) {
      eax@1 = a0@2;
      return eax@1;
    }
    """)
    return

  def test_multiple_register_argument(self):

    input = """
      eax = method(edi, edx);
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@4, a1@5) {
      eax@3 = method(a0@4, a1@5);
      return eax@3;
    }
    """)
    return

  def test_simple_stack_argument(self):

    input = """
      eax = *(esp + 4);
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@3) {
      eax@1 = a0@3;
      return eax@1;
    }
    """)
    return

  def test_stack_variable_not_renamed(self):

    input = """
      eax = *(esp - 4);
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func() {
      eax@1 = *(esp@0 - 4)@2;
      return eax@1;
    }
    """)
    return

  def test_multiple_stack_argument(self):

    input = """
      eax = method(*(esp + 4), *(esp + 8));
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@4, a1@5) {
      eax@1 = method(a0@4, a1@5);
      return eax@1;
    }
    """)
    return

  def test_argument_many_references(self):

    input = """
      edi = *(esp + 4);
      edx = *(esp + 4);
      eax = method();
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@5) {
      edi@1 = a0@5;
      edx@2 = a0@5;
      eax@3 = method(edi@1, edx@2);
      return eax@3;
    }
    """)
    return

  def test_assign_register_argument(self):

    input = """
      eax = edi;
      edi = 1;
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@3) {
      eax@1 = a0@3;
      a0@4 = 1;
      return eax@1;
    }
    """)
    return

  def test_assign_stack_argument(self):

    input = """
      eax = *(esp + 4);
      *(esp + 4) = 1;
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@4) {
      eax@1 = a0@4;
      a0@5 = 1;
      return eax@1;
    }
    """)
    return

  def test_restored_not_argument(self):

    input = """
      *(esp - 4) = edi;
      edi = 1;
      eax = method();
      edi = *(esp - 4);
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func() {
      *(esp@0 - 4)@5 = edi@1;
      edi@2 = 1;
      eax@3 = method(edi@2);
      edi@4 = *(esp@0 - 4)@5;
      return eax@3;
    }
    """)
    return

  def test_restored_argument(self):

    input = """
      *(esp - 4) = edi;
      eax = method(edi);
      edi = *(esp - 4);
      return eax;
    """

    self.assert_uninitialized(input, ['edi@1', 'esp@0'])
    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@5) {
      *(esp@0 - 4)@4 = a0@5;
      eax@2 = method(a0@5);
      a0@6 = *(esp@0 - 4)@4;
      return eax@2;
    }
    """)
    return

  def test_deref_of_argument(self):
    """ when there is a deref of a location, like `eax = *(edi + 4)`
        and both `edi` and `*(edi + 4)` are uninitialized, only the
        innermost uninitialized location is an argument. """

    input = """
      eax = *(edi - 4);
      return eax;
    """

    self.assert_step(decompiler.step_arguments_renamed, input, """
    func(a0@3) {
      eax@1 = *(a0@3 - 4)@2;
      return eax@1;
    }
    """)
    return

if __name__ == '__main__':
  unittest.main()
