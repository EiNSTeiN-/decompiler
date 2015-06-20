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
    if type(stmt) == goto_t and stmt.is_known():
      if stmt.expr.value in function.blocks:
        next = function.blocks[stmt.expr.value]
        loop_t.visit(function, next, loops, visited, context[:])
    elif type(stmt) == branch_t:
      if stmt.true.value in function.blocks:
        next = function.blocks[stmt.true.value]
        loop_t.visit(function, next, loops, visited, context[:])
      if stmt.false.value in function.blocks:
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
    if type(stmt) == goto_t and stmt.is_known():
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
    return

class controlflow_common_t(object):
  def trim(self, blocks):
    """ remove blocks from the given list if
        they are no longer part of the function. """
    for block in blocks[:]:
      if block.ea not in self.function.blocks.keys():
        blocks.remove(block)
    return

  def expand_branches(self, blocks=None):
    for stmt in iterators.statement_iterator_t(self.function):
      if type(stmt) != branch_t:
        continue
      if blocks and stmt.container.block not in blocks:
        continue
      condition = stmt.expr.copy()
      goto_true = goto_t(stmt.ea, stmt.true.copy())
      goto_false = goto_t(stmt.ea, stmt.false.copy())
      _if = if_t(stmt.ea, condition, container_t(stmt.container.block, [goto_true]))
      simplify_expressions.run(_if.expr, deep=True)
      stmt.container.insert(stmt.index(), _if)
      stmt.container.insert(stmt.index(), goto_false)
      stmt.remove()
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

class loop_reconstructor_t(controlflow_common_t):

  def __init__(self, cf, loop):
    self.cf = cf
    self.function = cf.function
    self.loop = loop
    return

  def is_do_while_loop(self):
    stmt = self.loop.start.container[-1]
    if type(stmt) == branch_t:
      branches = (self.function.blocks[stmt.true.value], self.function.blocks[stmt.false.value])
      if len(set(branches).intersection(self.loop.exits)) == 1 and self.loop.start in branches:
        return True
    return False

  def wrap_loop(self, ea, klass, block, condition):
    ctn = container_t(block, block.container[:])
    block.container[:] = []
    _while = klass(ea, condition, ctn)
    block.container.add(_while)
    if type(ctn[-1]) == goto_t:
      self.remove_goto(ctn, block)
    return _while

  def run(self):
    self.loop.started = True

    if self.loop.condition_block is self.loop.start:
      if len(self.loop.blocks) == 1 and len(self.loop.start.container) > 1:
        # edge case for single-block do-while loop
        self.reconstruct_do_while_loop(self.loop.condition_block)
      else:
        self.reconstruct_while_loop()
      return

    self.cf.reconstruct_forward(self.loop.blocks, self.prioritize_non_conditional_block,
      exclude=[self.loop.condition_block])
    if self.is_do_while_loop():
      self.reconstruct_do_while_loop(self.loop.start)
    else:
      _while = self.wrap_loop(None, while_t, self.loop.blocks[0], value_t(1, 1))
      self.cleanup_loop(_while, self.loop.blocks[0], self.loop.exit_block)
    return

  def reaches_to(self, block, end_block, visited):
    if block in visited:
      return False
    visited.append(block)
    to = block.jump_to_ea
    if end_block.ea in to:
      return True
    for ea in to:
      if ea in self.function.blocks:
        to_block = self.function.blocks[ea]
        if self.reaches_to(to_block, end_block, visited[:]):
          return True
    return False

  def prioritize_non_conditional_block(self, left, right):
    """ Choose which block between left and right should be
        reconstructed first. This prioritizer returns the first
        block that never reaches the loop's conditional block,
        or if both reaches it, the longest path first. """
    #print 'prioritize non conditional block', repr(left.container), 'or', repr(right.container)
    if self.loop.condition_block:
      left_reach = self.reaches_to(left, self.loop.condition_block, [])
      right_reach = self.reaches_to(right, self.loop.condition_block, [])
      if left_reach and right_reach:
        return self.prioritize_longest_path(left, right)
      elif left_reach:
        return right
      elif right_reach:
        return left
    return self.prioritize_longest_path(left, right)

  def prioritize_longest_path(self, left, right):
    """ Choose which block between left and right should be
        reconstructed first. This prioritizer returns whichever
        block creates the longest path inside of the loop's blocks. """
    #print 'prioritize longest', repr(left.container), 'or', repr(right.container)
    left_reach = self.reaches_to(left, self.loop.start, [])
    right_reach = self.reaches_to(right, self.loop.start, [])
    #print 'left_reach', repr(left_reach)
    #print 'right_reach', repr(right_reach)
    if not left_reach and not right_reach:
      return
    elif not left_reach:
      return left
    elif not right_reach:
      return right
    return

  def reconstruct_do_while_loop(self, condition_block):
    stmt = condition_block.container[-1]
    condition = stmt.expr
    branches = (self.function.blocks[stmt.true.value], self.function.blocks[stmt.false.value])
    exit, = list(set(branches).intersection(self.loop.exits))
    stmt.remove()

    """
    blocks = self.loop.blocks
    blocks.remove(condition_block)
    if len(blocks) > 0:
      self.cf.reconstruct_forward(blocks)
      if len(self.loop.blocks) != 1:
        raise RuntimeError('something went wrong :(')
      blocks.append(condition_block)
      self.cf.reconstruct_forward(blocks)
    blocks.append(condition_block)
    """
    self.cf.reconstruct_forward(self.loop.blocks)
    _while = self.wrap_loop(stmt.ea, do_while_t, self.loop.blocks[0], condition.copy())
    self.cleanup_loop(_while, self.loop.blocks[0], exit)
    return

  def reconstruct_while_loop(self):
    # remove the branch going into the loop and leave only a way to exit the loop.
    if len(self.loop.start.container) == 1:
      block = self.loop.condition_block
      stmt = block.container[-1]
      condition = stmt.expr
      dest, = list(set(block.jump_to).difference(self.loop.exits))
      stmt.remove()
      block.container.add(goto_t(stmt.ea, value_t(dest.ea, self.function.arch.address_size)))
    else:
      condition = value_t(1, 1)
      block = self.loop.condition_block
      stmt = block.container[-1]
      dest, = list(set(block.jump_to).difference(self.loop.exits))
      stmt.remove()
      ctn = container_t(block, [break_t(stmt.ea)])
      _if = if_t(stmt.ea, b_not_t(stmt.expr.copy()), ctn)
      block.container.add(_if)
      simplify_expressions.run(_if.expr, deep=True)

    # collapse all the loop blocks into a single container
    #print repr(self.loop.blocks)
    self.cf.reconstruct_forward(self.loop.blocks, self.prioritize_longest_path)
    #print repr(self.loop.blocks)

    # build the new while loop.
    block = self.loop.blocks[0]
    _while = self.wrap_loop(stmt.ea, while_t, block, condition.copy())
    block.container.add(goto_t(None, value_t(self.loop.exit_block.ea, self.function.arch.address_size)))
    self.cleanup_loop(_while, block, self.loop.exit_block)
    return

  def cleanup_loop(self, stmt, loop_block, exit_block):
    if not stmt.container:
      return
    self.expand_branches(self.loop.blocks)
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

class conditional_reconstructor_t(controlflow_common_t):

  def __init__(self, cf, conditional, prioritizer=None):
    self.cf = cf
    self.function = cf.function
    self.conditional = conditional
    self.prioritizer = prioritizer
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

  def run(self):
    self.cf.reconstruct_forward(self.conditional.left, self.prioritizer)
    self.cf.reconstruct_forward(self.conditional.right, self.prioritizer)

    if len(self.conditional.left) == 0 and len(self.conditional.right) == 0:
      return

    if type(self.conditional.top.container[-1]) not in (goto_t, branch_t):
      return

    if self.conditional.top in [loop.start for loop in self.cf.loops]:
      return

    if len(self.conditional.left) > 0:
      then_blocks, else_blocks = self.conditional.left, self.conditional.right
    else:
      then_blocks, else_blocks = self.conditional.right, self.conditional.left
    expr = self.conditional_expr(self.conditional.top, then_blocks[0])
    stmt = self.conditional.top.container[-1]
    stmt.remove()

    prioritized = False
    if self.prioritizer and len(then_blocks) > 0 and len(else_blocks) > 0:
      first = self.prioritizer(then_blocks[0], else_blocks[0])
      if first is else_blocks[0]:
        then_blocks, else_blocks = else_blocks, then_blocks
        expr = b_not_t(expr)
      prioritized = True

    then_ctn = self.cf.assembler.build_container(container_t(self.conditional.top), then_blocks, self.prioritizer)
    else_ctn = self.cf.assembler.build_container(container_t(self.conditional.top), else_blocks, self.prioritizer)

    if not prioritized and else_ctn and type(then_ctn[0]) in (if_t, branch_t) and type(else_ctn[0]) not in (if_t, branch_t):
      then_ctn, else_ctn = else_ctn, then_ctn
      expr = b_not_t(expr)
    _if = if_t(stmt.ea, expr, then_ctn, else_ctn)
    simplify_expressions.run(_if.expr, deep=True)
    self.conditional.top.container.add(_if)
    self.conditional.top.container.add(goto_t(stmt.ea, value_t(self.conditional.bottom.ea, self.function.arch.address_size)))

    self.remove_goto(then_ctn, self.conditional.bottom)
    if else_ctn:
      self.remove_goto(else_ctn, self.conditional.bottom)

    return

class assembler_t(controlflow_common_t):

  def __init__(self, function):
    self.function = function
    return

  def build_container(self, container, blocks, prioritizer=None, exclude=[]):
    """ take all statements in each of the given blocks
        and put them in a new container in the best way possible. """
    if len(blocks) == 0:
      return None
    while len(blocks) > 0:
      block = blocks.pop(0)
      self.assemble_connected(container, blocks, block, prioritizer, exclude)
      self.trim(blocks)
    return container

  def assemble_connected(self, container, blocks, block, prioritizer=None, exclude=[]):
    for stmt in block.container:
      container.add(stmt)
    if block is not self.function.entry_block:
      self.function.blocks.pop(block.ea)
    if block not in exclude:
      self.connect_next(container, blocks, prioritizer, exclude)
    return

  def connect_next(self, container, blocks, prioritizer=None, exclude=[]):
    stmt = container[-1]
    if type(stmt) == goto_t and stmt.expr.value in self.function.blocks:
      dest = self.function.blocks[stmt.expr.value]
      if dest in blocks or (len(list(dest.jump_from)) == 1 and not dest.node.is_return_node and dest not in exclude):
        stmt.remove()
        self.assemble_connected(container, blocks, dest, prioritizer, exclude)
    elif type(stmt) == branch_t:
      dest_true, dest_false = None, None
      if stmt.true.value in self.function.blocks:
        dest_true = self.function.blocks[stmt.true.value]
      if stmt.false.value in self.function.blocks:
        dest_false = self.function.blocks[stmt.false.value]

      expr = stmt.expr.copy()
      if prioritizer and dest_true and dest_false:
        first = prioritizer(dest_true, dest_false)
        if first is dest_false:
          dest_true, dest_false = dest_false, dest_true
          expr = b_not_t(expr)

      true_ctn = container_t(container.block, [])
      _if = if_t(stmt.ea, expr, true_ctn, None)
      simplify_expressions.run(_if.expr, deep=True)
      container.add(_if)
      stmt.remove()

      if dest_true and (dest_true in blocks or (len(list(dest_true.jump_from)) == 1 and not dest_true.node.is_return_node and dest_true not in exclude)):
        self.assemble_connected(true_ctn, blocks, dest_true, prioritizer, exclude)
      else:
        true_ctn.add(goto_t(None, stmt.true.copy()))

      if dest_false and (dest_false in blocks or (len(list(dest_false.jump_from)) == 1 and not dest_false.node.is_return_node and dest_true not in exclude)):
        self.assemble_connected(container, blocks, dest_false, prioritizer, exclude)
      else:
        container.add(goto_t(None, stmt.false.copy()))
    return

class controlflow_t(controlflow_common_t):
  def __init__(self, function):
    self.function = function
    self.loops = loop_t.find(function)
    conditional_t.merge_conditions(function)
    self.conditionals = conditional_t.find(function)

    self.assembler = assembler_t(self.function)
    return

  @property
  def prioritizer(self):
    return self.prioritizers[-1]

  def reconstruct(self):
    self.reconstruct_forward(self.function.blocks.values())
    self.expand_branches()
    return

  def reconstruct_forward(self, blocks, prioritizer=None, exclude=[]):
    if len(blocks) == 0:
      return

    # check if any loops are present, as they must be
    # reconstructed from the inside out.
    for loop in reversed(self.loops):
      if loop.started:
        continue
      if loop.start in blocks:
        loop_reconstructor_t(self, loop).run()

    # next attempt to reconstruct conditionals
    for cond in self.conditionals:
      if cond.top in blocks and cond.top not in [loop.start for loop in self.loops]:
        conditional_reconstructor_t(self, cond, prioritizer).run()

    # compact all the remaining blocks together, the best possible way.
    self.trim(blocks)
    if len(blocks) > 1:
      first = blocks[0]
      container = self.assembler.build_container(container_t(first), blocks, prioritizer, exclude)
      if container:
        first.container = container
      self.function.blocks[first.ea] = first
      if not first in blocks:
        blocks.append(first)
      self.trim(blocks)

    if len(blocks) != 1:
      raise RuntimeError('something went wrong :(')
    return

  def reconstruct_backwards(self, blocks, start):

    return

def run(function):
  """ combine until no more combinations can be applied. """
  c = controlflow_t(function)
  #print 'loops', repr(c.loops)
  #print 'conditionals', repr(c.conditionals)
  c.reconstruct()
  return
