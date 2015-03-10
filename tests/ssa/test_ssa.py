
import re
import unittest
import sys
sys.path.append('./tests')
sys.path.append('./src')

from common.ply import ir_parser
from common.disassembler import parser_disassembler
import decompiler
from decompiler import decompiler_t
from output import c
import ssa
from expressions import *

class TestSSA(unittest.TestCase):

  def __init__(self, *args):
    unittest.TestCase.__init__(self, *args)
    self.maxDiff = None
    return

  def unindent(self, text):
    text = re.sub(r'^[\s]*\n', '', text)
    text = re.sub(r'\n[\s]*$', '', text)
    lines = text.split("\n")
    indents = [re.match(r'^[\s]*', line) for line in lines if line.strip() != '']
    lengths = [(len(m.group(0)) if m else 0) for m in indents]
    indent = min(lengths)
    unindented = [line[indent:] for line in lines]
    return "\n".join(unindented)

  def assert_ssa_form(self, input, expected):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_SSA_DONE:
        break

    t = c.tokenizer(d.flow, indent='  ')
    tokens = list(t.flow_tokens())

    result = self.unindent(''.join([str(t) for t in tokens]))

    expected = self.unindent(expected)
    self.assertMultiLineEqual(expected, result)

    return

  def get_ssa_tagged_registers(self, input):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_IR_DONE:
        break

    tagger = ssa.ssa_tagger_t(d.flow)
    tagger.tag_registers()

    return d.flow, tagger

  def get_ssa_tagged_derefs(self, input):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_IR_DONE:
        break

    tagger = ssa.ssa_tagger_t(d.flow)
    tagger.tag_registers()
    tagger.tag_derefs()

    return d.flow, tagger

  def deep_tokenize(self, flow, input):

    if isinstance(input, dict):
      tokenized = {}
      for left, right in input.iteritems():
        tkey =self.deep_tokenize(flow, left)
        tokenized[tkey] = self.deep_tokenize(flow, right)
      return tokenized
    elif isinstance(input, list):
      return [self.deep_tokenize(flow, expr) for expr in input]
    elif isinstance(input, assignable_t) or isinstance(input, expr_t):
      t = c.tokenizer(flow)
      tokens = list(t.expression_tokens(input))
      return ''.join([str(t) for t in tokens])

    raise

  def assert_ssa_aliases(self, input, expected):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_SSA_DONE:
        break

    actual = {}

    for block in d.flow.iterblocks():
      for stmt in block.container.statements:
        for expr in stmt.expressions:
          for deref in expr.iteroperands():
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

if __name__ == '__main__':
  unittest.main()
