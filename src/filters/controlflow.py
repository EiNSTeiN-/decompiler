""" Control flow simplification algorithms.

This file contains algorithms for transforming the control flow into the most
readable form possible.

When the run() routine is called, the control flow is mostly flat, and
consist mostly of normal statements, conditional jump statements of the form
'if(...) goto ...' and unconditional jump statements of the form 'goto ...'
(without preceding condition). Most of the work done here is applying simple
algorithms to eliminate goto statements.
"""

import simplify_expressions
import iterators

from expressions import *
from statements import *

class loop_t(object):

  def __init__(self, blocks):
    self.started = False

    self.start = blocks[0]
    self.blocks = blocks
    self.function = self.start.function

    self.find_entries()
    self.find_exits()
    self.attach_breaks()

    self.condition_block = None
    self.exit_block = None
    self.find_condition()
    return

  def __repr__(self):
    return '<%s %x>' % (self.__class__.__name__, self.start.ea)

  def find_entries(self):
    """ Find blocks that lead to this loop but are not part of it. """
    entries = set(self.start.jump_from)
    self.entries = entries.difference(self.blocks)
    return

  def find_exits(self):
    """ Find blocks that this loop leads into and that are not part of it. """
    downwards = []
    loop_t.visit(self.function, self.start, [], downwards, [])
    leads_to = set()
    for block in self.blocks:
      leads_to = leads_to.union(block.jump_to)
    leads_to = leads_to.difference(self.blocks)
    self.exits = list(leads_to)
    return

  def reaches_to(self, block, to):
    visited = []
    loop_t.visit(self.function, block, [], visited, [])
    return to in visited

  def find_condition(self):
    exit_block = list(set(self.start.jump_to).difference(self.blocks))
    if len(exit_block) == 1 and exit_block[0] in self.exits:
      #print 'the first block in this loop leads to an exit block', repr(exit_block[0])
      self.condition_block = self.start
      self.exit_block = exit_block[0]
    else:
      for block in self.blocks:
        to = set(block.jump_to)
        if len(to.intersection(self.exits)) == 1 and self.start in to:
          self.condition_block = block
          self.exit_block = list(to.intersection(self.exits))[0]
          return
    return

  def attach_breaks(self):
    """ find blocks that could be attached to the loop as break statements. """
    for exit in self.exits:
      to = list(exit.jump_to)
      if len(to) == 1 and to[0] is not exit and to[0] in self.exits:
        self.exits.remove(exit)
        self.blocks.append(exit)
    return

  @staticmethod
  def visit(function, block, loops, visited, context):
    if block in context:
      added = False
      for loop in loops:
        if loop[0] is block:
          for _block in context[context.index(block):]:
            if _block not in loop:
              loop.append(_block)
          added = True
      if not added:
        loops.append(context[context.index(block):])
      return
    context.append(block)
    if block not in visited:
      visited.append(block)
    if len(block.container) == 0:
      return
    stmt = block.container[-1]
    if type(stmt) == goto_t:
      next = function.blocks[stmt.expr.value]
      loop_t.visit(function, next, loops, visited, context[:])
    elif type(stmt) == branch_t:
      next = function.blocks[stmt.true.value]
      loop_t.visit(function, next, loops, visited, context[:])
      next = function.blocks[stmt.false.value]
      loop_t.visit(function, next, loops, visited, context[:])
    return

  @staticmethod
  def find(function):
    loops = []
    loop_t.visit(function, function.entry_block, loops, [], [])
    return [loop_t(blocks) for blocks in loops]

class conditional_t(object):

  def __init__(self, top, left, right, bottom):
    self.top = top
    self.left = left
    self.right = right
    self.bottom = bottom
    return

  def __repr__(self):
    return '<%s from:%s left:%s right:%s to:%s>' % (self.__class__.__name__,
      self.top, self.left, self.right, self.bottom)

  @staticmethod
  def diff(priors, context):
    prior = list(reversed(priors[context[-1]]))
    ctx = list(reversed(context[:-1]))
    for block in ctx:
      if block not in prior:
        continue
      i = prior.index(block)
      left = list(reversed(prior[1:i]))
      right = list(reversed(ctx[:ctx.index(block)]))
      return conditional_t(block, left, right, prior[0])
    return

  @staticmethod
  def visit(function, block, conds, visited, context, priors):
    if block in visited:
      diff = conditional_t.diff(priors, context + [block])
      if diff:
        conds.append(diff)
      return
    context.append(block)
    priors[block] = context[:]
    if block not in visited:
      visited.append(block)
    if len(block.container) == 0:
      return
    stmt = block.container[-1]
    if type(stmt) == goto_t:
      next = function.blocks[stmt.expr.value]
      conditional_t.visit(function, next, conds, visited, context[:], priors)
    elif type(stmt) == branch_t:
      next = function.blocks[stmt.true.value]
      conditional_t.visit(function, next, conds, visited, context[:], priors)
      next = function.blocks[stmt.false.value]
      conditional_t.visit(function, next, conds, visited, context[:], priors)
    return

  @staticmethod
  def find(function):
    conditionals = []
    conditional_t.visit(function, function.entry_block, conditionals, [], [], {})
    return conditionals

class controlflow_t(object):
  def __init__(self, function):
    self.function = function
    self.loops = loop_t.find(function)
    self.conditionals = conditional_t.find(function)
    return

  def reconstruct(self):
    self.reconstruct_blocks(list(self.function.blocks.values()))
    return

  def reconstruct_loop(self, loop):
    loop.started = True
    print 'reconstructing loop', repr(loop)
    self.reconstruct_blocks(loop.blocks)
    return

  def conditional_expr(self, src, dest):
    branch = src.container[-1]
    if branch.true.value == dest.ea:
      return branch.expr.copy()
    elif branch.false.value == dest.ea:
      return b_not_t(branch.expr.copy())
    else:
      raise RuntimeError('something went wrong :(')
    return

  def squish(self, parent_block, blocks):

    if len(blocks) == 0:
      return None

    ctn = container_t(parent_block)

    for block in blocks:
      for stmt in block.container:
        ctn.add(stmt)
      self.function.blocks.pop(block.ea)

    return ctn

  def remove_goto(self, ctn, block):
    """ remove goto going to block at the end of the given container """
    if type(ctn[-1]) == goto_t and ctn[-1].expr.value == block.ea:
      ctn[-1].remove()
    else:
      raise RuntimeError('something went wrong :(', repr(ctn))
    return

  def trim(self, blocks):
    for block in blocks[:]:
      if block.ea not in self.function.blocks.keys():
        blocks.remove(block)
    return

  def reconstruct_conditional(self, cond):
    print 'reconstructing conditional 1', repr(cond)
    self.reconstruct_blocks(cond.left)
    self.reconstruct_blocks(cond.right)
    print 'reconstructing conditional 2', repr(cond)

    if len(cond.left) == 0 and len(cond.right) == 0:
      return

    then_blocks, else_blocks = (cond.left, cond.right) if len(cond.left) > 0 else (cond.right, cond.left)
    print repr(then_blocks), repr(else_blocks)
    expr = self.conditional_expr(cond.top, then_blocks[0])
    stmt = cond.top.container[-1]
    stmt.remove()

    then_ctn = self.squish(cond.top, then_blocks)
    else_ctn = self.squish(cond.top, else_blocks)
    goto = then_ctn[-1]
    self.remove_goto(then_ctn, cond.bottom)
    if else_ctn:
      self.remove_goto(else_ctn, cond.bottom)
      if type(then_ctn[0]) == if_t and type(else_ctn[0]) != if_t:
        then_ctn, else_ctn = else_ctn, then_ctn
        expr = b_not_t(expr)
    _if = if_t(expr, then_ctn, else_ctn)
    simplify_expressions.run(_if.expr, deep=True)
    cond.top.container.add(_if)

    cond.top.container.add(goto.copy())

    return

  def reconstruct_blocks(self, blocks):
    print 'reconstructing blocks', repr(blocks)
    # check if any loops are present, as they must be
    # reconstructed from the inside out.
    for loop in reversed(self.loops):
      if loop.started:
        continue
      #print repr(loop.start), repr(blocks)
      if loop.start in blocks:
        self.reconstruct_loop(loop)
    # next attempt to reconstruct conditionals
    for cond in self.conditionals:
      if cond.top in blocks:
        self.reconstruct_conditional(cond)
    self.trim(blocks)
    return

def run(function):
  """ combine until no more combinations can be applied. """
  c = controlflow_t(function)
  print 'loops', repr(c.loops)
  print 'conditionals', repr(c.conditionals)
  c.reconstruct()
  return
