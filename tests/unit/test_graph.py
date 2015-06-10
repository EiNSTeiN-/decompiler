# coding=utf-8

import unittest

import test_helper
import decompiler

class TestGraph(test_helper.TestHelper):

  def get_graph(self, input):
    d = self.decompile_until(input, decompiler.step_basic_blocks)
    return d.graph

  def test_simple(self):
    """ Test simple function without jumps create a single block. """

    graph = self.get_graph("""
      a = 1;
      return a;
    """)
    nodes = graph.nodes

    self.assertEqual(1, len(nodes))
    self.assertEqual([0], nodes.keys())

    self.assertEqual(0, nodes[0].ea)
    self.assertEqual([0,1], nodes[0].items)
    self.assertEqual([], nodes[0].jump_from)
    self.assertEqual([], nodes[0].jump_to)
    self.assertEqual(None, nodes[0].falls_into)

    self.assertEqual([0], [node.ea for node in graph.iternodes()])
    return

  def test_goto(self):
    """ Test goto creates a separate block. """

    graph = self.get_graph("""
         goto 100;
    100: return a;
    """)
    nodes = graph.nodes

    self.assertEqual(2, len(nodes))
    self.assertEqual([0,1], nodes.keys())

    self.assertEqual(0, nodes[0].ea)
    self.assertEqual([0], nodes[0].items)
    self.assertEqual([], nodes[0].jump_from)
    self.assertEqual([nodes[1]], nodes[0].jump_to)
    self.assertEqual(None, nodes[0].falls_into)

    self.assertEqual(1, nodes[1].ea)
    self.assertEqual([1], nodes[1].items)
    self.assertEqual([nodes[0]], nodes[1].jump_from)
    self.assertEqual([], nodes[1].jump_to)
    self.assertEqual(None, nodes[1].falls_into)

    self.assertEqual([0,1], [node.ea for node in graph.iternodes()])
    return

  def test_if(self):
    """ Test 'if' creates 3 blocks.

    if (a)
      a = 2;
    return a;
    """

    graph = self.get_graph("""
          a = 1;
          if (b != 0) goto 300;
          a = 2;
    300:  return a;
    """)
    nodes = graph.nodes

    self.assertEqual(3, len(nodes))
    self.assertEqual([0,2,3], nodes.keys())

    self.assertEqual(0, nodes[0].ea)
    self.assertEqual([0,1], nodes[0].items)
    self.assertEqual([], nodes[0].jump_from)
    self.assertEqual([nodes[3], nodes[2]], nodes[0].jump_to)
    self.assertEqual(None, nodes[0].falls_into)

    self.assertEqual(2, nodes[2].ea)
    self.assertEqual([2], nodes[2].items)
    self.assertEqual([nodes[0]], nodes[2].jump_from)
    self.assertEqual([nodes[3]], nodes[2].jump_to)
    self.assertEqual(nodes[3], nodes[2].falls_into)

    self.assertEqual(3, nodes[3].ea)
    self.assertEqual([3], nodes[3].items)
    self.assertEqual([nodes[0], nodes[2]], nodes[3].jump_from)
    self.assertEqual([], nodes[3].jump_to)
    self.assertEqual(None, nodes[3].falls_into)

    self.assertEqual([0,3,2], [node.ea for node in graph.iternodes()])
    return

  def test_recursive_goto(self):
    """ Test recursive 'goto' works. Block should be linked from and to itself. """

    graph = self.get_graph("""
    300:  goto 300;
    """)
    nodes = graph.nodes

    self.assertEqual(1, len(nodes))
    self.assertEqual([0], nodes.keys())

    self.assertEqual(0, nodes[0].ea)
    self.assertEqual([0], nodes[0].items)
    self.assertEqual([nodes[0]], nodes[0].jump_from)
    self.assertEqual([nodes[0]], nodes[0].jump_to)
    self.assertEqual(None, nodes[0].falls_into)

    self.assertEqual([0], [node.ea for node in graph.iternodes()])
    return

if __name__ == '__main__':
  unittest.main()
