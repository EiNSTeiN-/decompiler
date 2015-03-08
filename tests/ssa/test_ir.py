
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

class TestIR(unittest.TestCase):

  def unindent(self, text):
    text = re.sub(r'^[\s]*\n', '', text)
    text = re.sub(r'\n[\s]*$', '', text)
    lines = text.split("\n")
    indents = [re.match(r'^[\s]*', line) for line in lines if line.strip() != '']
    lengths = [(len(m.group(0)) if m else 0) for m in indents]
    indent = min(lengths)
    unindented = [line[indent:] for line in lines]
    return "\n".join(unindented)

  def assert_ir(self, input, expected):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_IR_DONE:
        break

    t = c.tokenizer(d.flow, indent='  ')
    tokens = list(t.flow_tokens())

    result = self.unindent(''.join([str(t) for t in tokens]))

    expected = self.unindent(expected)
    self.assertMultiLineEqual(result, expected)

    return

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

    self.assert_ir(input, expected)
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

    self.assert_ir(input, expected)
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

    loc_3:
      return a;

    loc_2:
      a = 2;
      goto loc_3;
    }
    """

    self.assert_ir(input, expected)
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

    self.assert_ir(input, expected)
    return

if __name__ == '__main__':
  unittest.main()
