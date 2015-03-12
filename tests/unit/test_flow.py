
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

class TestFlow(unittest.TestCase):

  def get_basic_blocks(self, input):

    ssa.ssa_context_t.index = 0
    dis = parser_disassembler(input)
    d = decompiler_t(dis, 0)

    for step in d.steps():
      print 'Decompiler step: %u - %s' % (step, decompiler_t.phase_name[step])
      if step >= decompiler.STEP_BASIC_BLOCKS_FOUND:
        break

    return d.flow

  def test_simple(self):
    """ Test simple function without jumps create a single block. """

    flow = self.get_basic_blocks("""
      a = 1;
      return a;
    """)
    blocks = flow.blocks

    self.assertEqual(1, len(blocks))
    self.assertEqual([0], blocks.keys())

    self.assertEqual(0, blocks[0].ea)
    self.assertEqual([0,1], blocks[0].items)
    self.assertEqual([], blocks[0].jump_from)
    self.assertEqual([], blocks[0].jump_to)
    self.assertEqual(None, blocks[0].falls_into)

    self.assertEqual([0], [block.ea for block in flow.iterblocks()])
    return

  def test_goto(self):
    """ Test goto creates a separate block. """

    flow = self.get_basic_blocks("""
         goto 100;
    100: return a;
    """)
    blocks = flow.blocks

    self.assertEqual(2, len(blocks))
    self.assertEqual([0,1], blocks.keys())

    self.assertEqual(0, blocks[0].ea)
    self.assertEqual([0], blocks[0].items)
    self.assertEqual([], blocks[0].jump_from)
    self.assertEqual([blocks[1]], blocks[0].jump_to)
    self.assertEqual(None, blocks[0].falls_into)

    self.assertEqual(1, blocks[1].ea)
    self.assertEqual([1], blocks[1].items)
    self.assertEqual([blocks[0]], blocks[1].jump_from)
    self.assertEqual([], blocks[1].jump_to)
    self.assertEqual(None, blocks[1].falls_into)

    self.assertEqual([0,1], [block.ea for block in flow.iterblocks()])
    return

  def test_if(self):
    """ Test 'if' creates 3 blocks.

    if (a)
      a = 2;
    return a;
    """

    flow = self.get_basic_blocks("""
          a = 1;
          if (b != 0) goto 300;
          a = 2;
    300:  return a;
    """)
    blocks = flow.blocks

    self.assertEqual(3, len(blocks))
    self.assertEqual([0,2,3], blocks.keys())

    self.assertEqual(0, blocks[0].ea)
    self.assertEqual([0,1], blocks[0].items)
    self.assertEqual([], blocks[0].jump_from)
    self.assertEqual([blocks[3], blocks[2]], blocks[0].jump_to)
    self.assertEqual(None, blocks[0].falls_into)

    self.assertEqual(2, blocks[2].ea)
    self.assertEqual([2], blocks[2].items)
    self.assertEqual([blocks[0]], blocks[2].jump_from)
    self.assertEqual([blocks[3]], blocks[2].jump_to)
    self.assertEqual(blocks[3], blocks[2].falls_into)

    self.assertEqual(3, blocks[3].ea)
    self.assertEqual([3], blocks[3].items)
    self.assertEqual([blocks[0], blocks[2]], blocks[3].jump_from)
    self.assertEqual([], blocks[3].jump_to)
    self.assertEqual(None, blocks[3].falls_into)

    self.assertEqual([0,3,2], [block.ea for block in flow.iterblocks()])
    return

  def test_recursive_goto(self):
    """ Test recursive 'goto' works. Block should be linked from and to itself. """

    flow = self.get_basic_blocks("""
    300:  goto 300;
    """)
    blocks = flow.blocks

    self.assertEqual(1, len(blocks))
    self.assertEqual([0], blocks.keys())

    self.assertEqual(0, blocks[0].ea)
    self.assertEqual([0], blocks[0].items)
    self.assertEqual([blocks[0]], blocks[0].jump_from)
    self.assertEqual([blocks[0]], blocks[0].jump_to)
    self.assertEqual(None, blocks[0].falls_into)

    self.assertEqual([0], [block.ea for block in flow.iterblocks()])
    return

if __name__ == '__main__':
  unittest.main()
