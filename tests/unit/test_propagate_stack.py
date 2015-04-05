import unittest

import test_helper
import decompiler
import ssa

class TestPropagateStack(test_helper.TestHelper):

  def assert_ssa_form(self, input, expected):
    d = self.decompile_until(input, decompiler.step_stack_propagated)
    result = self.tokenize(d.flow)

    expected = self.unindent(expected)
    self.assertMultiLineEqual(expected, result)
    return

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

    self.assert_ssa_form(input, expected)
    return

  def test_theta_simple(self):

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

    loc_3:
      esp@1 = 2;
      goto loc_4;

    loc_1:
      esp@3 = 1;
      goto loc_4;

    loc_4:
      esp@2 = THETA(esp@1, esp@3, );
      return esp@2;
    }
    """

    self.assert_ssa_form(input, expected)
    return

  def test_theta_if_else(self):

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
      esp@1 = esp@0 + 4;
      goto loc_5 if(a@2 > 1) else goto loc_3;

    loc_5:
      *(esp@0 + 4) = 2;
      goto loc_6;

    loc_3:
      *(esp@0 + 4) = 1;
      goto loc_6;

    loc_6:
      return 1;
    }
    """

    self.assert_ssa_form(input, expected)
    return

if __name__ == '__main__':
  unittest.main()
