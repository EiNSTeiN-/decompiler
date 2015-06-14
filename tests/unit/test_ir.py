# coding=utf-8

import unittest

import test_helper
import decompiler

class TestIR(test_helper.TestHelper):

  def test_simple(self):
    """ Test simple function with single block. """

    input = """
      a = 1;
      return a;
    """

    expected = """
    func() {
      a = 1;
      return a;
    }
    """

    self.assert_step(decompiler.step_ir_form, input, expected)
    return

  def test_goto(self):
    """ Test function with goto. """

    input = """
         goto 100;
    100: return a;
    """

    expected = """
    func() {
      goto loc_1;
    loc_1:
      return a;
    }
    """

    self.assert_step(decompiler.step_ir_form, input, expected)
    return

  def test_if(self):
    """ Test 'if' creates 3 blocks.

    if (a)
      a = 2;
    return a;
    """

    input = """
          a = 1;
          if (b != 0) goto 300;
          a = 2;
    300:  return a;
    """

    expected = """
    func() {
      a = 1;
      goto loc_3 if(b != 0) else goto loc_2;
    loc_2:
      a = 2;
      goto loc_3;
    loc_3:
      return a;
    }
    """

    self.assert_step(decompiler.step_ir_form, input, expected)
    return

  def test_recursive_goto(self):
    """ Test recursive 'goto' works. Block should be linked from and to itself. """

    input = """
    300:  goto 300;
    """

    expected = """
    func() {
    loc_0:
      goto loc_0;
    }
    """

    self.assert_step(decompiler.step_ir_form, input, expected)
    return

if __name__ == '__main__':
  unittest.main()
