import unittest

import test_helper
import decompiler
import ssa
from expressions import *

class TestSSA(test_helper.TestHelper):

  def assert_ssa_form(self, input, expected):
    d = self.decompile_until(input, decompiler.STEP_SSA_DONE)
    result = self.tokenize(d.flow)

    expected = self.unindent(expected)
    self.assertMultiLineEqual(expected, result)
    return

  def get_ssa_tagged_registers(self, input):
    d = self.decompile_until(input, decompiler.STEP_IR_DONE)
    tagger = ssa.ssa_tagger_t(d.flow)
    tagger.tag_registers()
    return d.flow, tagger

  def get_ssa_tagged_derefs(self, input):
    d = self.decompile_until(input, decompiler.STEP_IR_DONE)
    tagger = ssa.ssa_tagger_t(d.flow)
    tagger.tag_registers()
    tagger.tag_derefs()
    return d.flow, tagger

  def assert_ssa_aliases(self, input, expected):
    d = self.decompile_until(input, decompiler.STEP_SSA_DONE)

    actual = {}

    for deref in decompiler.operand_iterator_t(d.flow):
      if isinstance(deref, deref_t):
        alts = [self.deep_tokenize(d.flow, alt) for alt in ssa.alternate_form_iterator_t(deref, include_self=False)]
        tokenized = self.deep_tokenize(d.flow, deref)
        actual[tokenized] = alts

    self.assertEqual(expected, actual)
    return

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

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    self.assert_ssa_form(input, expected)
    self.assert_ssa_aliases(input, {})
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

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(s@0 + 4)@1': [],
      '*(s@0 + 8)@2': [],
      '*(s@0 + 4)@3': []})
    return

  def test_alias_deref(self):
    """ Check that *(a + 8) and *(s + 4) are correctly aliased and get the same index. """

    input = """
      a = s;
      *(a + 8) = 1;
      s = s + 4;
      return *(s + 4);
    """

    expected = """
    func() {
      a@1 = s@0;
      *(a@1 + 8)@3 = 1;
      s@2 = s@0 + 4;
      return *(s@2 + 4)@3;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({flow.blocks[0]: []}, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(a@1 + 8)@3': ['*(s@0 + 8)'],
      '*(s@2 + 4)@3': ['*(s@0 + 8)']})
    return

  def test_theta_if_1(self):
    """ Test inclusion of theta functions in simple 'if' block.

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

    loc_3:
      a@2 = THETA(a@0, a@3, );
      return a@2;

    loc_2:
      a@3 = 2;
      goto loc_3;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['b@1'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[2]: [],
      flow.blocks[3]: [flow.blocks[3].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['b@1'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[2]: [],
      flow.blocks[3]: [],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {})
    return

  def test_theta_if_2(self):
    """ Test inclusion of theta functions in simple 'if-then-else' block.

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

    loc_3:
      a@1 = 1;
      goto loc_4;

    loc_1:
      a@3 = 2;
      goto loc_4;

    loc_4:
      a@2 = THETA(a@1, a@3, );
      return a@2;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['a@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[3]: [],
      flow.blocks[4]: [flow.blocks[4].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['a@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[3]: [],
      flow.blocks[4]: [],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {})
    return

  def test_theta_while(self):
    """ Test inclusion of theta functions in simple 'while' loop.

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
      i@1 = THETA(i@0, i@4, );
      goto loc_4 if(i@1 >= 100) else goto loc_2;

    loc_4:
      i@2 = THETA(i@1, );
      return i@2;

    loc_2:
      i@3 = THETA(i@1, );
      i@4 = i@3 + 1;
      goto loc_1;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[0]],
      flow.blocks[4]: [flow.blocks[4].container[0]],
      flow.blocks[2]: [flow.blocks[2].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[4]: [],
      flow.blocks[2]: [],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {})
    return

  def test_theta_do_while(self):
    """ Test inclusion of theta functions in simple 'do-while' loop.

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
      i@1 = THETA(i@0, i@2, );
      i@2 = i@1 + 1;
      goto loc_1 if(i@2 < 100) else goto loc_3;

    loc_3:
      i@3 = THETA(i@2, );
      return i@3;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[0]],
      flow.blocks[3]: [flow.blocks[3].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual([], tagger.uninitialized)
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[3]: [],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {})
    return

  def test_theta_deref_do_while(self):
    """ Test inclusion of theta functions in 'do-while' loop with dereferences
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
      i@1 = THETA(i@0, );
      *(i@1)@4 = THETA(*(i@0)@3, *(i@1)@5, );
      *(i@1)@5 = *(i@1)@4 + 1;
      goto loc_1 if(*(i@1)@5 < 100) else goto loc_3;

    loc_3:
      i@2 = THETA(i@1, );
      *(i@2)@6 = THETA(*(i@1)@5, );
      return *(i@2)@6;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['i@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[0]],
      flow.blocks[3]: [flow.blocks[3].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['i@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[1]],
      flow.blocks[3]: [flow.blocks[3].container[1]],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(i@0)@3': [],
      '*(i@1)@4': ['*(i@0)'],
      '*(i@1)@5': ['*(i@0)'],
      '*(i@2)@6': ['*(i@1)', '*(i@0)']})
    return

  def test_theta_deref_do_while_2(self):
    """ Test inclusion of theta functions in 'do-while' loop with dereferences
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
      i@1 = THETA(i@0, i@2, );
      i@2 = i@1 + 1;
      *(i@2)@6 = *(i@2)@5 + 1;
      goto loc_1 if(*(i@2)@6 < 100) else goto loc_4;

    loc_4:
      i@3 = THETA(i@2, );
      *(i@3)@7 = THETA(*(i@2)@6, );
      return *(i@3)@7;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['i@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[0]],
      flow.blocks[4]: [flow.blocks[4].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['i@0', '*(i@2)@5'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[4]: [flow.blocks[4].container[1]],
    }, tagger.block_thetas)

    self.assert_ssa_aliases(input, {
      '*(i@0)@4': [],
      '*(i@2)@5': ['*(i@1 + 1)', '*(i@0 + 1)', '*(i@2 + 1)'],
      '*(i@2)@6': ['*(i@1 + 1)', '*(i@0 + 1)', '*(i@2 + 1)'],
      '*(i@3)@7': ['*(i@2)', '*(i@1 + 1)', '*(i@0 + 1)', '*(i@2 + 1)']})
    return

  def test_theta_deref_1(self):
    """ Test inclusion of theta functions for dereferences in simple 'if' block.

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

    loc_2:
      s@1 = THETA(s@0, s@2, );
      *(s@1 + 4)@4 = THETA(*(s@0 + 4)@3, *(s@2 + 4)@5, );
      return *(s@1 + 4)@4;

    loc_1:
      s@2 = THETA(s@0, );
      *(s@2 + 4)@5 = 1;
      goto loc_2;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[2]: [flow.blocks[2].container[0]],
      flow.blocks[1]: [flow.blocks[1].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0', '*(s@0 + 4)@3'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
      flow.blocks[2]: [flow.blocks[2].container[1]],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(s@0 + 4)@3': [],
      '*(s@1 + 4)@4': ['*(s@0 + 4)', '*(s@2 + 4)'],
      '*(s@2 + 4)@5': ['*(s@0 + 4)'],
      })
    return

  def test_theta_deref_2(self):
    """ Test inclusion of theta functions for dereferences with aliasing
        in 'if' block: *(s + 8), *(a + c) and *(a + 4) should be correctly
        aliased and get theta-functions.

    a = s + 4;
    if (*(s + 8) == 0) {
        c = 4;
        *(a + c) = *(s + 8) + 1;
    }
    return *(a + 4);
    """

    input = """
          a = s + 4;
          if (*(s + 8) != 0) goto 300;

          c = 4;
          *(a + c) = *(s + 8) + 1;

    300:  return *(a + 4);
    """

    expected = """
    func() {
      a@1 = s@0 + 4;
      goto loc_4 if(*(s@0 + 8)@6 != 0) else goto loc_2;

    loc_4:
      a@2 = THETA(a@1, a@4, );
      *(a@2 + 4)@7 = THETA(*(s@0 + 8)@6, *(a@4 + c@3)@9, );
      return *(a@2 + 4)@7;

    loc_2:
      c@3 = 4;
      a@4 = THETA(a@1, );
      s@5 = THETA(s@0, );
      *(s@5 + 8)@8 = THETA(*(s@0 + 8)@6, );
      *(a@4 + c@3)@9 = *(s@5 + 8)@8 + 1;
      goto loc_4;
    }
    """

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[4]: [flow.blocks[4].container[0]],
      flow.blocks[2]: [flow.blocks[2].container[1], flow.blocks[2].container[2]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0', '*(s@0 + 8)@6'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[2]: [flow.blocks[2].container[3]],
      flow.blocks[4]: [flow.blocks[4].container[1]],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(s@0 + 8)@6': [],
      '*(a@2 + 4)@7': ['*(a@1 + 4)', '*(a@4 + 4)', '*(s@0 + 8)'],
      '*(s@5 + 8)@8': ['*(s@0 + 8)'],
      '*(a@4 + c@3)@9': ['*(a@1 + c@3)', '*(a@1 + 4)', '*(s@0 + 4 + c@3)', '*(s@0 + 8)'],
      })
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

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0', '*(s@0 + 4)@2'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
    }, tagger.block_thetas)

    self.assert_ssa_form(input, expected)

    self.assert_ssa_aliases(input, {
      '*(s@0 + 4)@2': [],
      '*(a@1 + 8)@3': ['*(*(s@0 + 4)@2 + 8)'],
      })
    return

  def test_theta_nested_deref(self):
    """ Deref of deref with theta functions """

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
      a@2 = THETA(a@1, a@3, );
      *(a@2 + 8)@5 = 0;
      a@3 = *(a@2 + 12)@6;
      goto loc_1;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_registers(input)
    self.assertEqual(['s@0'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [flow.blocks[1].container[0]],
    }, tagger.block_thetas)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['s@0', '*(s@0 + 4)@4', '*(a@2 + 12)@6'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({
      flow.blocks[0]: [],
      flow.blocks[1]: [],
    }, tagger.block_thetas)

    self.assert_ssa_aliases(input, {
      '*(a@2 + 12)@6': ['*(a@1 + 12)',
                        '*(a@3 + 12)',
                        '*(*(s@0 + 4)@4 + 12)',
                        '*(*(a@2 + 12)@6 + 12)',
                        '*(*(a@1 + 12)@6 + 12)',
                        '*(*(a@3 + 12)@6 + 12)'],
      '*(a@2 + 8)@5': ['*(a@1 + 8)',
                       '*(a@3 + 8)',
                       '*(*(s@0 + 4)@4 + 8)',
                       '*(*(a@2 + 12)@6 + 8)',
                       '*(*(a@1 + 12)@6 + 8)',
                       '*(*(a@3 + 12)@6 + 8)'],
      '*(s@0 + 4)@4': []})
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

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', 'ebp@1'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'ebp@3': 'ebp@1', 'esp@0': 'esp@0'}, self.deep_tokenize(flow, tagger.restored_locations()))

    return

  def test_simple_restored_deref(self):
    """ Find restored dereference location """

    input = """
      edi = *(esp + 14);
      *(esp + 14) = 123;
      *(esp + 14) = edi;
      return 0;
    """

    expected = """
    func() {
      edi@1 = *(esp@0 + 14)@2;
      *(esp@0 + 14)@3 = 123;
      *(esp@0 + 14)@4 = edi@1;
      return 0;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', '*(esp@0 + 14)@2'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'*(esp@0 + 14)@4': '*(esp@0 + 14)@2', 'esp@0': 'esp@0'}, self.deep_tokenize(flow, tagger.restored_locations()))

    return

  def test_theta_restored_reg(self):
    """ Find restored registers with tetha values """

    input = """
          *(esp) = ebp;
          if(a > 1) goto 100;
          ebp = 123;
    100:  eax = ebp;
          ebp = *(esp);
          return eax;
    """

    expected = """
    func() {
      *(esp@0)@8 = ebp@1;
      goto loc_3 if(a@2 > 1) else goto loc_2;

    loc_3:
      ebp@3 = THETA(ebp@1, ebp@7, );
      eax@4 = ebp@3;
      esp@5 = THETA(esp@0, esp@0, );
      *(esp@5)@9 = THETA(*(esp@0)@8, *(esp@0)@8, );
      ebp@6 = *(esp@5)@9;
      return eax@4;

    loc_2:
      ebp@7 = 123;
      goto loc_3;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', 'ebp@1', 'a@2'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'ebp@6': 'ebp@1', 'esp@5': 'esp@0', 'a@2': 'a@2'}, self.deep_tokenize(flow, tagger.restored_locations()))

    return

  def test_theta_restored_reg_recursive(self):
    """ Find restored register location in recursive flows """

    input = """
          *(esp) = ebp;
          ebp = 0;
    200:  eax = ebp; // just something to trigger a recursion
          ebp = eax;
          if(ebp < 234) goto 200;
          ebp = *(esp);
          return 0;
    """

    expected = """
    func() {
      *(esp@0)@8 = ebp@1;
      ebp@2 = 0;
      goto loc_2;

    loc_2:
      ebp@3 = THETA(ebp@2, ebp@5, );
      eax@4 = ebp@3;
      ebp@5 = eax@4;
      goto loc_2 if(ebp@5 < 234) else goto loc_5;

    loc_5:
      esp@6 = THETA(esp@0, );
      *(esp@6)@9 = THETA(*(esp@0)@8, );
      ebp@7 = *(esp@6)@9;
      return 0;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', 'ebp@1'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'ebp@7': 'ebp@1', 'esp@6': 'esp@0'}, self.deep_tokenize(flow, tagger.restored_locations()))

    return

  def test_theta_restored_reg_multireturn_agree(self):
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
      *(esp@0)@14 = ebp@1;
      ebp@2 = 0;
      goto loc_7 if(edi@3 > 1) else goto loc_3;

    loc_7:
      eax@4 = 1;
      esp@5 = THETA(esp@0, );
      *(esp@5)@15 = THETA(*(esp@0)@14, );
      ebp@6 = *(esp@5)@15;
      return eax@4;

    loc_3:
      edi@7 = THETA(edi@3, );
      goto loc_a if(edi@7 > 2) else goto loc_4;

    loc_a:
      eax@8 = 2;
      esp@9 = THETA(esp@0, );
      *(esp@9)@16 = THETA(*(esp@0)@14, );
      ebp@10 = *(esp@9)@16;
      return eax@8;

    loc_4:
      eax@11 = 0;
      esp@12 = THETA(esp@0, );
      *(esp@12)@17 = THETA(*(esp@0)@14, );
      ebp@13 = *(esp@12)@17;
      return eax@11;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', 'ebp@1', 'edi@3'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'ebp@10': 'ebp@1', 'ebp@13': 'ebp@1',
      'ebp@6': 'ebp@1', 'edi@3': 'edi@3', 'edi@7': 'edi@3', 'esp@12': 'esp@0',
      'esp@5': 'esp@0', 'esp@9': 'esp@0'},
      self.deep_tokenize(flow, tagger.restored_locations()))

    return

  def test_theta_restored_reg_multireturn_disagree(self):
    """ Find restored registers with multiple return sites """

    input = """
          *(esp) = ebp;
          ebp = 0;
          if(edi > 1) goto 100;

          ebp = *(esp);
          return 0;

    100:  ebp = 0;
          return 0;
    """

    expected = """
    func() {
      *(esp@0)@7 = ebp@1;
      ebp@2 = 0;
      goto loc_5 if(edi@3 > 1) else goto loc_3;

    loc_5:
      ebp@4 = 0;
      return 0;

    loc_3:
      esp@5 = THETA(esp@0, );
      *(esp@5)@8 = THETA(*(esp@0)@7, );
      ebp@6 = *(esp@5)@8;
      return 0;
    }
    """

    self.assert_ssa_form(input, expected)

    flow, tagger = self.get_ssa_tagged_derefs(input)
    self.assertEqual(['esp@0', 'ebp@1', 'edi@3'], self.deep_tokenize(flow, tagger.uninitialized))
    self.assertEqual({'edi@3': 'edi@3', 'esp@0': 'esp@0', 'esp@5': 'esp@0'}, self.deep_tokenize(flow, tagger.restored_locations()))

    return

if __name__ == '__main__':
  unittest.main()
