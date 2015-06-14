""" Control flow reconstruction.

Transforms the control flow into the most readable form possible.
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
    self.entries = list(entries.difference(self.blocks))
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
    if len(self.left) == 0 and len(self.right) != 0:
      self.left, self.right = self.right, self.left
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
        for cond in conds:
          if cond.top is diff.top:
            return
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

  @staticmethod
  def is_branch_block(block):
    """ return True if the last statement in a block is a branch statement. """
    return len(block.container) >= 1 and type(block.container[-1]) == branch_t

  @staticmethod
  def invert_goto_condition(stmt):
    """ invert the goto at the end of a block for the goto in
        the if_t preceding it """

    stmt.true.value, stmt.false.value = stmt.false.value, stmt.true.value

    stmt.expr = b_not_t(stmt.expr.pluck())
    simplify_expressions.run(stmt.expr, deep=True)

    return

  @classmethod
  def combine_branch_blocks(cls, function, this, next):
    """ combine two if_t that jump to the same destination into a boolean or expression. """

    left = [this.container[-1].true.value, this.container[-1].false.value]
    right = [next.container[-1].true.value, next.container[-1].false.value]

    dest = list(set(left).intersection(set(right)))

    if len(dest) != 1:
      return False

    # both blocks have one jump in common.
    dest = dest[0]

    if this.container[-1].false.value == dest:
      cls.invert_goto_condition(this.container[-1])

    if next.container[-1].false.value == dest:
      cls.invert_goto_condition(next.container[-1])

    common = function.blocks[dest]
    exit = function.blocks[next.container[-1].false.value]

    if exit == this:
      cls = b_and_t
    else:
      cls = b_or_t

    stmt = this.container[-1]
    stmt.expr = cls(stmt.expr.copy(), next.container[-1].expr.copy())
    simplify_expressions.run(stmt.expr, deep=True)

    this.container[-1].false = next.container[-1].false

    function.blocks.pop(next.ea)

    return True

  @classmethod
  def combine_conditions(cls, block):
    """ combine two ifs into a boolean or (||) or a boolean and (&&). """

    if not cls.is_branch_block(block):
      return False

    for next in block.jump_to:
      if not cls.is_branch_block(next) or len(next.container) != 1:
        continue

      if cls.combine_branch_blocks(block.function, block, next):
        return True

    return False

  @classmethod
  def merge_conditions(cls, function):
    """ perform merge of some conditional statements that can be merged without problem """
    merged = None
    while merged is not False:
      for block in function.blocks.values():
        merged = cls.combine_conditions(block)
        if merged:
          break

class controlflow_t(object):
  def __init__(self, function):
    self.function = function
    self.loops = loop_t.find(function)
    conditional_t.merge_conditions(function)
    self.conditionals = conditional_t.find(function)
    return

  def reconstruct(self):
    self.reconstruct_blocks(list(self.function.blocks.values()))
    return

  def is_do_while_loop(self, loop):
    stmt = loop.start.container[-1]
    if type(stmt) == branch_t:
      branches = (self.function.blocks[stmt.true.value], self.function.blocks[stmt.false.value])
      if len(set(branches).intersection(loop.exits)) == 1 and loop.start in branches:
        return True
    return False

  def reconstruct_loop(self, loop):
    loop.started = True

    if loop.condition_block is loop.start:
      if len(loop.blocks) == 1 and len(loop.start.container) > 1:
        # edge case for single-block do-while loop
        self.reconstruct_do_while_loop(loop)
      else:
        self.reconstruct_while_loop(loop)
      return

    blocks = loop.blocks
    if loop.condition_block:
      blocks.remove(loop.condition_block)
    self.reconstruct_blocks(blocks)
    self.trim(loop.blocks)
    self.trim(loop.entries)
    self.trim(loop.exits)

    if len(loop.blocks) != 1:
      raise RuntimeError('something went wrong :(')
      return

    if self.is_do_while_loop(loop):
      self.reconstruct_do_while_loop(loop)
    else:
      block = loop.blocks[0]
      ctn = container_t(block, block.container[:])
      block.container[:] = []
      _while = while_t(None, value_t(1, 1), ctn)
      loop.start.container.add(_while)
      if type(ctn[-1]) == goto_t:
        self.remove_goto(ctn, block)
      self.cleanup_loop(_while, block, loop.exit_block)
    return

  def reconstruct_do_while_loop(self, loop):
    stmt = loop.start.container[-1]
    condition = stmt.expr
    branches = (self.function.blocks[stmt.true.value], self.function.blocks[stmt.false.value])
    exit = list(set(branches).intersection(loop.exits)).pop(0)
    stmt.remove()

    block = loop.blocks[0]
    ctn = container_t(block, block.container[:])
    block.container[:] = []
    _while = do_while_t(None, condition.copy(), ctn)
    loop.start.container.add(_while)
    self.remove_goto(ctn, block)
    block.container.add(goto_t(None, value_t(exit.ea, self.function.arch.address_size)))
    self.cleanup_loop(_while, block, exit)
    return

  def reconstruct_while_loop(self, loop):
    # remove the branch going into the loop and leave only a way to exit the loop.
    if len(loop.start.container) == 1:
      block = loop.condition_block
      stmt = block.container[-1]
      condition = stmt.expr
      dest = list(set(block.jump_to).difference(loop.exits)).pop(0)
      stmt.remove()
      block.container.add(goto_t(stmt.ea, value_t(dest.ea, self.function.arch.address_size)))
    else:
      condition = value_t(1, 1)

      block = loop.condition_block
      stmt = block.container[-1]
      dest = list(set(block.jump_to).difference(loop.exits)).pop(0)
      stmt.remove()
      ctn = container_t(block, [break_t(stmt.ea)])
      _if = if_t(None, b_not_t(stmt.expr.copy()), ctn)
      block.container.add(_if)
      simplify_expressions.run(_if.expr, deep=True)

    # collapse all the loop blocks into a single container
    self.reconstruct_blocks(loop.blocks)
    self.trim(loop.blocks)
    self.trim(loop.entries)
    self.trim(loop.exits)

    if not len(loop.blocks) == 1:
      raise RuntimeError('something went wrong :(')

    # build the new while loop.
    block = loop.blocks[0]
    ctn = container_t(block, block.container[:])
    block.container[:] = []
    _while = while_t(None, condition.copy(), ctn)
    block.container.add(_while)
    self.remove_goto(ctn, block)
    block.container.add(goto_t(None, value_t(loop.exit_block.ea, self.function.arch.address_size)))
    self.cleanup_loop(_while, block, loop.exit_block)
    return

  def cleanup_loop(self, stmt, loop_block, exit_block):
    if not stmt.container:
      return
    if type(stmt) == goto_t and stmt.expr.value == exit_block.ea:
      stmt.container.insert(stmt.index(), break_t(stmt.ea))
      stmt.remove()
    elif type(stmt) == goto_t and stmt.expr.value == loop_block.ea:
      stmt.container.insert(stmt.index(), continue_t(stmt.ea))
      stmt.remove()
    else:
      for _stmt in stmt.statements:
        self.cleanup_loop(_stmt, loop_block, exit_block)
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
    """ take all statements in each of the given blocks
        and put them in a new container in the best way possible. """
    if len(blocks) == 0:
      return None
    container = container_t(parent_block)
    while len(blocks) > 0:
      block = blocks.pop(0)
      self.squish_connected(container, blocks, block)
      self.trim(blocks)
    return container

  def squish_connected(self, container, blocks, block):
    for stmt in block.container:
      container.add(stmt)
    if block is not self.function.entry_block:
      self.function.blocks.pop(block.ea)

    self.connect_next(container, blocks)
    return

  def connect_next(self, container, blocks):
    stmt = container[-1]
    if type(stmt) == goto_t and stmt.expr.value in self.function.blocks:
      dest = self.function.blocks[stmt.expr.value]
      if dest in blocks or (len(list(dest.jump_from)) == 1 and not dest.node.is_return_node):
        stmt.remove()
        self.squish_connected(container, blocks, dest)
    elif type(stmt) == branch_t:
      dest_true, dest_false = None, None
      if stmt.true.value in self.function.blocks:
        dest_true = self.function.blocks[stmt.true.value]
      if stmt.false.value in self.function.blocks:
        dest_false = self.function.blocks[stmt.false.value]

      #if dest_true in blocks or dest_false in blocks:
      true_ctn = container_t(container.block, [])
      #false_ctn = container_t(container.block, [])
      _if = if_t(stmt.ea, stmt.expr.copy(), true_ctn, None)
      container.add(_if)
      stmt.remove()

      if dest_true and (dest_true in blocks or (len(list(dest_true.jump_from)) == 1 and not dest_true.node.is_return_node)):
        self.squish_connected(true_ctn, blocks, dest_true)
      else:
        true_ctn.add(goto_t(None, stmt.true.copy()))

      if dest_false and (dest_false in blocks or (len(list(dest_false.jump_from)) == 1 and not dest_false.node.is_return_node)):
        self.squish_connected(container, blocks, dest_false)
      else:
        container.add(goto_t(None, stmt.false.copy()))
    return

  def remove_goto(self, ctn, block):
    """ remove goto going to block at the end of the given container """
    stmt = ctn[-1]
    if type(stmt) == goto_t and stmt.expr.value == block.ea:
      stmt.remove()
    elif type(stmt) == branch_t:
      if stmt.true.value == block.ea:
        condition = b_not_t(stmt.expr.pluck())
        goto = goto_t(None, stmt.false.copy())
      elif stmt.false.value == block.ea:
        condition = stmt.expr.pluck()
        goto = goto_t(None, stmt.true.copy())
      else:
        return
      _if = if_t(stmt.ea, condition, container_t(block, [goto]))
      simplify_expressions.run(_if.expr, deep=True)
      ctn.add(_if)
      stmt.remove()

      self.connect_next(_if.then_expr, [])
      self.remove_goto(_if.then_expr, block)
    return

  def trim(self, blocks):
    """ remove blocks from the given list if
        they are no longer part of the function. """
    for block in blocks[:]:
      if block.ea not in self.function.blocks.keys():
        blocks.remove(block)
    return

  def reconstruct_conditional(self, cond):
    self.reconstruct_blocks(cond.left)
    self.reconstruct_blocks(cond.right)

    if len(cond.left) == 0 and len(cond.right) == 0:
      return

    if type(cond.top.container[-1]) not in (goto_t, branch_t):
      return

    if cond.top in [loop.start for loop in self.loops]:
      return

    then_blocks, else_blocks = (cond.left, cond.right) if len(cond.left) > 0 else (cond.right, cond.left)
    expr = self.conditional_expr(cond.top, then_blocks[0])
    stmt = cond.top.container[-1]
    stmt.remove()

    then_ctn = self.squish(cond.top, then_blocks)
    else_ctn = self.squish(cond.top, else_blocks)

    if else_ctn and type(then_ctn[0]) in (if_t, branch_t) and type(else_ctn[0]) not in (if_t, branch_t):
      then_ctn, else_ctn = else_ctn, then_ctn
      expr = b_not_t(expr)
    _if = if_t(stmt.ea, expr, then_ctn, else_ctn)
    simplify_expressions.run(_if.expr, deep=True)
    cond.top.container.add(_if)
    cond.top.container.add(goto_t(None, value_t(cond.bottom.ea, self.function.arch.address_size)))

    self.remove_goto(then_ctn, cond.bottom)
    if else_ctn:
      self.remove_goto(else_ctn, cond.bottom)

    return

  def reconstruct_blocks(self, blocks):
    # check if any loops are present, as they must be
    # reconstructed from the inside out.
    for loop in reversed(self.loops):
      if loop.started:
        continue
      if loop.start in blocks:
        self.reconstruct_loop(loop)

    # next attempt to reconstruct conditionals
    for cond in self.conditionals:
      if cond.top in blocks and cond.top not in [loop.start for loop in self.loops]:
        self.reconstruct_conditional(cond)

    # compact all the remaining blocks together, the best possible way.
    self.trim(blocks)
    if len(blocks) > 1:
      first = blocks[0]
      container = self.squish(first, blocks)
      if container:
        first.container = container
      self.function.blocks[first.ea] = first
      if not first in blocks:
        blocks.append(first)
      self.trim(blocks)
    return

def run(function):
  """ combine until no more combinations can be applied. """
  c = controlflow_t(function)
  #print 'loops', repr(c.loops)
  #print 'conditionals', repr(c.conditionals)
  c.reconstruct()
  return
