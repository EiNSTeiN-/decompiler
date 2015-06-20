# coding=utf-8

import unittest

import test_helper
import decompiler
import ssa

class TestPrune(test_helper.TestHelper):

  def test_prune_register(self):
    """ Unused registers are removed. """

    input = """
      a = 1;
      b = 2;
      b = 3;
      return a + b;
    """

    expected = """
    func() {
      a@0 = 1;
      b@2 = 3;
      return a@0 + b@2;
    }
    """

    self.assert_step(decompiler.step_registers_pruned, input, expected)
    return

  def test_do_not_prune_calls(self):
    """ calls are never removed. """

    input = """
      a = method(1,2);
      return a;
    """

    expected = """
    func() {
      a@1 = method(1, 2);
      return a@1;
    }
    """

    self.assert_step(decompiler.step_registers_pruned, input, expected)
    return

  def test_prune_register_recursively(self):
    """ Unused registers are removed. """

    input = """
      a = 1;
      b = a;
      c = b;
      return a;
    """

    expected = """
    func() {
      a@0 = 1;
      return a@0;
    }
    """

    self.assert_step(decompiler.step_registers_pruned, input, expected)
    return

if __name__ == '__main__':
  unittest.main()
