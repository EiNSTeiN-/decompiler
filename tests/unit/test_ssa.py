# coding=utf-8

import unittest

import test_helper
import decompiler
import iterators
import ssa
from expressions import *

class TestSSA(test_helper.TestHelper):

  def assert_restored_locations(self, input, expected):
    dec = self.decompile_until(input, decompiler.step_ssa_form_derefs)
    actual = self.deep_tokenize(dec.function, dec.restored_locations)
    self.assertEqual(expected, actual)
    return

  def assert_live_ranges(self, step, input, expected):
    dec = self.decompile_until(input, step)
    lri = ssa.live_range_iterator_t(dec.function)
    allstmts = [id(stmt) for stmt in iterators.statement_iterator_t(dec.function)]
    actual = {}
    for lr in lri.live_ranges():
      stmts = lr.statements
      t = self.deep_tokenize(dec.function, lr.definition)
      if t not in actual:
        actual[t] = []
      actual[t].append([allstmts.index(id(stmt)) for stmt in stmts])
    self.assertEqual(expected, actual)

  def test_normal_regs(self):
    """ Test proper renaming of all register locations. """

    input = """
      a = 1;
      b = 2;
      a = a + b;
      return a;
    """

    expected = """
    func() {
      a@0 = 1;
      b@1 = 2;
      a@2 = a@0 + b@1;
      return a@2;
    }
    """

    self.assert_uninitialized(input, [])
    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    step = decompiler.step_ssa_form_registers
    self.assert_live_ranges(step, input, {
      'a@0': [[0, 1, 2]],
      'b@1': [[1, 2]],
      'a@2': [[2, 3]],
    })
    return

  def test_normal_deref(self):
    """ Test proper renaming of all dereference locations. """

    input = """
      *(s+4) = 1;
      *(s+8) = 2;
      *(s+4) = *(s+4) + *(s+8);
      return *(s+4);
    """
    expected = """
    func() {
      *(s@0 + 4)@1 = 1;
      *(s@0 + 8)@2 = 2;
      *(s@0 + 4)@3 = *(s@0 + 4)@1 + *(s@0 + 8)@2;
      return *(s@0 + 4)@3;
    }
    """

    self.assert_uninitialized(input, ['s@0'])
    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    return

  def test_alias_deref(self):
    """ Check that *(a + 8) and *(s + 4) are correctly aliased and get the same index. """

    input = """
      a = esp;
      *(a + 8) = 1;
      esp = esp + 4;
      return *(esp + 4);
    """

    expected = """
    func() {
      *(esp@0 + 8)@3 = 1;
      return *(esp@0 + 8)@3;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['esp@0'])
    return

  def test_phi_if_1(self):
    """ Test inclusion of phi functions in simple 'if' block.

    a = 1;
    if (b == 0)
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
      a@0 = 1;
      goto loc_3 if(b@1 != 0) else goto loc_2;
    loc_2:
      a@3 = 2;
      goto loc_3;
    loc_3:
      a@2 = Φ(a@0, a@3, );
      return a@2;
    }
    """

    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    self.assert_uninitialized(input, ['b@1'])
    return

  def test_phi_if_2(self):
    """ Test inclusion of phi functions in simple 'if-then-else' block.

    if (a == 0)
      a = 1;
    else
      a = 2;
    return a;
    """

    input = """
          if (a == 0) goto 200;
          a = 2;
          goto 300;
    200:  a = 1;
    300:  return a;
    """

    expected = """
    func() {
      goto loc_3 if(!(a@0)) else goto loc_1;
    loc_1:
      a@3 = 2;
      goto loc_4;
    loc_3:
      a@1 = 1;
      goto loc_4;
    loc_4:
      a@2 = Φ(a@3, a@1, );
      return a@2;
    }
    """

    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    self.assert_uninitialized(input, ['a@0'])
    return

  def test_phi_while(self):
    """ Test inclusion of phi functions in simple 'while' loop.

    i = 0;
    while (i < 100) {
      i = i + 1;
    }
    return i;
    """

    input = """
          i = 0;
    100:  if (i >= 100) goto 400;
          i = i + 1;
          goto 100;
    400:  return i;
    """

    expected = """
    func() {
      i@0 = 0;
      goto loc_1;
    loc_1:
      i@1 = Φ(i@0, i@2, );
      goto loc_4 if(i@1 >= 100) else goto loc_2;
    loc_2:
      i@2 = i@1 + 1;
      goto loc_1;
    loc_4:
      return i@1;
    }
    """

    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    self.assert_uninitialized(input, [])
    self.assert_live_ranges(decompiler.step_ssa_form_registers, input, {
      'i@0': [[0, 1, 2]],
      'i@2': [[4, 5, 2]],
      'i@1': [[2, 3], [2,3,6], [2,3,4]],
    })
    return

  def test_phi_do_while(self):
    """ Test inclusion of phi functions in simple 'do-while' loop.

    i = 0;
    do {
      i = i + 1;
    } while (i < 100);
    return i;
    """

    input = """
          i = 0;
    200:  i = i + 1;
          if (i < 100) goto 200;
          return i;
    """

    expected = """
    func() {
      i@0 = 0;
      goto loc_1;
    loc_1:
      i@1 = Φ(i@0, i@2, );
      i@2 = i@1 + 1;
      goto loc_1 if(i@2 < 100) else goto loc_3;
    loc_3:
      return i@2;
    }
    """

    self.assert_uninitialized(input, [])
    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    self.assert_live_ranges(decompiler.step_ssa_form_registers, input, {
      'i@0': [[0, 1, 2]],
      'i@1': [[2, 3]],
      'i@2': [[3, 4, 2], [3, 4], [3, 4, 5]],
    })
    return

  def test_phi_deref_do_while(self):
    """ Test inclusion of phi functions in 'do-while' loop with dereferences
        where deref target is aliased to itself.

    *(i) = 0;
    do {
        *(i) = *(i) + 1;
    } while (*(i) < 100);
    return *(i);
    """

    input = """
          *(i) = 0;
    200:  *(i) = *(i) + 1;
          if (*(i)< 100) goto 200;
          return *(i);
    """

    expected = """
    func() {
      *(i@0)@3 = 0;
      goto loc_1;
    loc_1:
      *(i@0)@4 = Φ(*(i@0)@3, *(i@0)@5, );
      *(i@0)@5 = *(i@0)@4 + 1;
      goto loc_1 if(*(i@0)@5 < 100) else goto loc_3;
    loc_3:
      return *(i@0)@5;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['i@0'])
    self.assert_live_ranges(decompiler.step_ssa_form_derefs, input, {
      '*(i@0)@3': [[0, 1, 2]],
      '*(i@0)@4': [[2, 3]],
      '*(i@0)@5': [[3, 4, 2], [3,4], [3,4,5]],
      'i@0': [[0]] + [[0,1,2]]*3 + [[0,1,2,3]]*2 + [[0, 1, 2, 3, 4], [0, 1, 2, 3, 4, 5]],
    })
    return

  def test_phi_deref_do_while_2(self):
    """ Test inclusion of phi functions in 'do-while' loop with dereferences
        where deref target is not aliased to itself.

    *(i) = 0;
    do {
      i = i + 1;
      *(i) = *(i) + 1;
    } while (*(i) < 100);
    return *(i);
    """

    input = """
          *(i) = 0;
    200:  i = i + 1;
          *(i) = *(i) + 1;
          if (*(i)< 100) goto 200;
          return *(i);
    """

    expected = """
    func() {
      *(i@0)@4 = 0;
      goto loc_1;
    loc_1:
      i@1 = Φ(i@0, i@2, );
      i@2 = i@1 + 1;
      *(i@2)@5 = Φ(*(i@2)@6, *(i@2)@7, );
      *(i@2)@7 = *(i@2)@5 + 1;
      goto loc_1 if(*(i@2)@7 < 100) else goto loc_4;
    loc_4:
      return *(i@2)@7;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['i@0', '*(i@2)@6'])
    self.assert_live_ranges(decompiler.step_ssa_form_derefs, input, {
      '*(i@0)@4': [[0]],
      '*(i@2)@5': [[4,5]],
      '*(i@2)@6': [[0,1,2,3,4]],
      '*(i@2)@7': [[5,6,2,3,4], [5,6], [5,6,7]],
      'i@0': [[0], [0, 1, 2]],
      'i@1': [[2, 3]],
      'i@2': [[3, 4, 5, 6, 2]] + [[3,4]]*3 + [[3,4,5]]*2 + [[3, 4, 5, 6], [3, 4, 5, 6, 7]],
    })
    return

  def test_phi_deref_1(self):
    """ Test inclusion of phi functions for dereferences in simple 'if' block.

    if (*(s+4) == 0)
        *(s+4) = 1;
    return *(s+4);
    """

    input = """
          if(*(s+4) == 0) goto 300;
          *(s+4) = 1;
    300:  return *(s+4);
    """

    expected = """
    func() {
      goto loc_2 if(!(*(s@0 + 4)@3)) else goto loc_1;
    loc_1:
      *(s@0 + 4)@5 = 1;
      goto loc_2;
    loc_2:
      *(s@0 + 4)@4 = Φ(*(s@0 + 4)@3, *(s@0 + 4)@5, );
      return *(s@0 + 4)@4;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['s@0', '*(s@0 + 4)@3'])
    return

  def test_simple_nested_deref(self):
    """ Deref of deref """

    input = """
      a = *(s + 4);
      *(a + 8) = 0;
      return *(a + 8);
    """

    expected = """
    func() {
      a@1 = *(s@0 + 4)@2;
      *(a@1 + 8)@3 = 0;
      return *(a@1 + 8)@3;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['s@0', '*(s@0 + 4)@2'])
    return

  def test_phi_nested_deref(self):
    """ Deref of deref with phi functions """

    input = """
         a = *(s + 4);
    100: *(a + 8) = 0;
         a = *(a + 12);
         goto 100;
    """

    expected = """
    func() {
      a@1 = *(s@0 + 4)@4;
      goto loc_1;
    loc_1:
      a@2 = Φ(a@1, a@3, );
      *(a@2 + 8)@5 = 0;
      a@3 = *(a@2 + 12)@7;
      goto loc_1;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['s@0', '*(s@0 + 4)@4', '*(a@2 + 12)@7'])
    return

  def test_simple_restored_register(self):
    """ Find restored register """

    input = """
      *(esp) = ebp;
      ebp = 123;
      ebp = *(esp);
      return 0;
    """

    expected = """
    func() {
      *(esp@0)@4 = ebp@1;
      ebp@2 = 123;
      ebp@3 = *(esp@0)@4;
      return 0;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['esp@0', 'ebp@1'])
    self.assert_restored_locations(input, {'ebp@3': 'ebp@1'})
    return

  def test_simple_restored_deref(self):
    """ Find restored dereference location """

    input = """
      edi = *(esp + 14);
      *(esp + 14) = 123;
      *(esp + 14) = edi;
      return;
    """

    expected = """
    func() {
      edi@1 = *(esp@0 + 14)@2;
      *(esp@0 + 14)@3 = 123;
      *(esp@0 + 14)@4 = edi@1;
      return;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['esp@0', '*(esp@0 + 14)@2'])
    self.assert_restored_locations(input, {'*(esp@0 + 14)@4': '*(esp@0 + 14)@2'})
    return

  def test_phi_restored_reg(self):
    """ Find restored registers with phi values """

    input = """
          *(edx) = ebp;
          if(a > 1) goto 100;
          ebp = 123;
    100:  edx = ebp;
          return edx;
    """

    expected = """
    func() {
      *(edx@0)@6 = ebp@1;
      goto loc_3 if(a@2 > 1) else goto loc_2;
    loc_2:
      ebp@4 = 123;
      goto loc_3;
    loc_3:
      ebp@3 = Φ(ebp@1, ebp@4, );
      edx@5 = ebp@3;
      return edx@5;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['edx@0', 'ebp@1', 'a@2'])
    self.assert_restored_locations(input, {})
    return

  def test_phi_restored_reg_recursive(self):
    """ Find restored register location in recursive flows """

    input = """
          *(esp) = ebp;
          ebp = 0;
    200:  eax = ebp; // just something to trigger a recursion
          ebp = eax;
          if(ebp < 234) goto 200;
          ebp = *(esp);
          return;
    """

    expected = """
    func() {
      *(esp@0)@9 = ebp@1;
      ebp@2 = 0;
      goto loc_2;
    loc_2:
      ebp@3 = Φ(ebp@2, ebp@4, );
      eax@5 = ebp@3;
      ebp@4 = eax@5;
      goto loc_2 if(ebp@4 < 234) else goto loc_5;
    loc_5:
      ebp@8 = *(esp@0)@9;
      return;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['esp@0', 'ebp@1'])
    self.assert_restored_locations(input, {'ebp@8': 'ebp@1'})
    return

  def test_phi_with_multiple_blocks(self):
    """ Find restored register location in recursive flows """

    input = """
          *(esp) = ebp;
          esp = esp - 4;
          ebp = esp;
          esp = esp - 40;
          *(ebp - 12) = 0;
    200:
          if(*(ebp - 12) < 30) goto 400;
    300:
          eax = 134515040;
          edx = *(ebp - 12);
          *(esp + 4) = edx;
          *(esp) = eax;
          eax = func1(eax, edx);
          *(ebp - 12) = *(ebp - 12) + 1;
          goto 200;
    400:
          eax = 0;
          esp = ebp;
          esp = esp + 4;
          ebp = *(esp);
          return eax;
    """

    expected = """
    func() {
      *(esp@0) = ebp@1;
      esp@2 = esp@0 - 4;
      ebp@3 = esp@2;
      esp@4 = esp@2 - 40;
      *(ebp@3 - 12) = 0;
      goto loc_5;
    loc_5:
      goto loc_d if(*(ebp@3 - 12) < 30) else goto loc_6;
    loc_6:
      eax@12 = 134515040;
      edx@13 = *(ebp@3 - 12);
      *(esp@4 + 4) = edx@13;
      *(esp@4) = eax@12;
      eax@16 = func1(eax@12, edx@13);
      *(ebp@3 - 12) = *(ebp@3 - 12) + 1;
      goto loc_5;
    loc_d:
      eax@7 = 0;
      esp@9 = ebp@3;
      esp@10 = esp@9 + 4;
      ebp@11 = *(esp@10);
      return eax@7;
    }
    """

    self.assert_step(decompiler.step_ssa_form_registers, input, expected)
    self.assert_uninitialized(input, ['esp@0', 'ebp@1'])
    self.assert_restored_locations(input, {'ebp@11': 'ebp@1', 'esp@10': 'esp@0'})
    return

  def test_phi_restored_reg_multireturn_agree(self):
    """ Find restored registers with multiple return sites """

    input = """
          *(esp) = ebp;
          ebp = 0;
          if(edi > 1) goto 200;
          if(edi > 2) goto 300;

          eax = 0;
          ebp = *(esp);
          return eax;

    200:  eax = 1;
          ebp = *(esp);
          return eax;

    300:  eax = 2;
          ebp = *(esp);
          return eax;
    """

    expected = """
    func() {
      *(esp@0)@15 = ebp@1;
      ebp@2 = 0;
      goto loc_7 if(edi@3 > 1) else goto loc_3;
    loc_3:
      goto loc_a if(edi@3 > 2) else goto loc_4;
    loc_4:
      eax@12 = 0;
      ebp@14 = *(esp@0)@15;
      return eax@12;
    loc_7:
      eax@4 = 1;
      ebp@6 = *(esp@0)@15;
      return eax@4;
    loc_a:
      eax@8 = 2;
      ebp@11 = *(esp@0)@15;
      return eax@8;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['edi@3', 'esp@0', 'ebp@1'])
    self.assert_restored_locations(input, {
      'ebp@11': 'ebp@1',
      'ebp@14': 'ebp@1',
      'ebp@6': 'ebp@1',
    })
    return

  def test_phi_restored_reg_multireturn_disagree(self):
    """ Find restored registers with multiple return sites """

    input = """
          *(esp) = ebp;
          ebp = 0;
          if(edi > 1) goto 100;

          ebp = *(esp);
          return;

    100:  ebp = 0;
          return;
    """

    expected = """
    func() {
      *(esp@0)@7 = ebp@1;
      ebp@2 = 0;
      goto loc_5 if(edi@3 > 1) else goto loc_3;
    loc_3:
      ebp@6 = *(esp@0)@7;
      return;
    loc_5:
      ebp@4 = 0;
      return;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    self.assert_uninitialized(input, ['edi@3', 'esp@0', 'ebp@1'])
    self.assert_restored_locations(input, {})

    return

  def test_phi_backtracking(self):

    input = """
          *(esp) = ebp;
          ebp = esp - 4;
          goto 200;
    100:  a = 0;
    200:  if (1 == 2) goto 100;
          ebp = *(ebp + 4);
          return;
    """

    expected = """
    func() {
      *(esp@0)@8 = ebp@1;
      goto loc_4;
    loc_3:
      a@3 = 0;
      goto loc_4;
    loc_4:
      goto loc_3 if(1 == 2) else goto loc_5;
    loc_5:
      ebp@7 = *(esp@0)@8;
      return;
    }
    """

    self.assert_step(decompiler.step_ssa_form_derefs, input, expected)
    return

if __name__ == '__main__':
  unittest.main()
