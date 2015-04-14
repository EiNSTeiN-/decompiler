from expressions import *
from statements import *

import filters.simplify_expressions
import filters.controlflow

class flowblock_t(object):

  def __init__(self, ea):

    self.ea = ea

    self.items = []
    self.container = container_t()

    self.jump_from = []
    self.jump_to = []

    self.falls_into = None

    return

  def add_jump_from(self, from_block):
    if from_block not in self.jump_from:
      self.jump_from.append(from_block)
    return

  def add_jump_to(self, to_block):
    if to_block not in self.jump_to:
      self.jump_to.append(to_block)
    return

  def __repr__(self):
    return '<flowblock %08x %s>' % (self.ea, repr(self.container), )

  def __str__(self):
    return str(self.container)

class flow_t(object):

  def __init__(self, entry_ea, arch, follow_calls=True):

    self.entry_ea = entry_ea
    self.follow_calls = follow_calls
    self.arch = arch

    self.func_items = self.arch.get_function_items(self.entry_ea)

    self.return_blocks = []

    self.entry_block = None
    self.blocks = {}

    return

  def __repr__(self):

    lines = []

    for block in self.iterblocks():
      lines.append('<loc_%x>' % (block.ea, ))
      lines += repr(block.container).split('\n')
      lines.append('')

    return '\n'.join(lines)

  def get_block(self, addr):

    if type(addr) == goto_t:
      if type(addr.expr) != value_t:
        raise RuntimeError('goto_t.expr is not value_t')

      ea = addr.expr.value

    elif type(addr) == value_t:
      ea = addr.value

    elif type(addr) in (long, int):
      ea = addr
    else:
      return

    if ea not in self.blocks:
      return None

    return self.blocks[ea]

  def remove_goto(self, block, stmt):
    """ remove a goto statement, and take care of unlinking the
        jump_to and jump_from.

        'block' is the block which contains the goto.
        'stmt' is the goto statement.
    """

    if type(stmt.expr) == value_t:
      dst_ea = stmt.expr.value
      dst_block = self.blocks[dst_ea]
      dst_block.jump_from.remove(block)
      block.jump_to.remove(dst_block)

    stmt.container.remove(stmt)
    return

  def jump_targets(self):
    """ find each point in the function which is the
    destination of a jump (conditional or not).

    jump destinations are the points that delimit new
    blocks. """

    for item in self.func_items:
      if self.arch.has_jump(item):
        for dest in self.arch.jump_branches(item):
          if type(dest) == value_t and dest.value in self.func_items:
            ea = dest.value
            yield ea

    return

  def find_control_flow(self):

    # find all jump targets
    jump_targets = list(set(self.jump_targets()))

    # prepare first block
    self.entry_block = flowblock_t(self.entry_ea)
    next_blocks = [self.entry_block, ]
    self.blocks[self.entry_ea] = self.entry_block

    # create all empty blocks.
    for target in jump_targets:
      if target in self.blocks.keys():
        continue
      block = flowblock_t(target)
      self.blocks[target] = block
      next_blocks.append(block)

    while len(next_blocks) > 0:

      # get next block
      block = next_blocks.pop(0)
      ea = block.ea

      while True:
        # append current ea to the block's locations array
        block.items.append(ea)

        if self.arch.is_return(ea):
          self.return_blocks.append(block)
          break

        elif self.arch.has_jump(ea):
          for dest in self.arch.jump_branches(ea):
            if type(dest) != value_t:
              print '%x: cannot follow jump to %s' % (ea, repr(dest))
              continue

            ea_to = dest.value
            if ea_to not in self.func_items:
              print '%x: jumped outside of function to %x' % (ea, ea_to, )
            else:
              toblock = self.blocks[ea_to]
              block.add_jump_to(toblock)
              toblock.add_jump_from(block)
          break

        next_ea = self.arch.next_instruction_ea(ea)

        if next_ea not in self.func_items:
          print '%x: jumped outside of function: %x' % (ea, next_ea)
          break

        ea = next_ea

        # the next instruction is part of another block...
        if ea in jump_targets:
          toblock = self.blocks[ea]
          block.add_jump_to(toblock)
          toblock.add_jump_from(block)

          block.falls_into = toblock
          break

    return

  def iterblocks(self):
    """ iterate over all blocks in the order that they most logically follow each other. """

    if not self.entry_block:
      return

    done = []
    blocks = [self.entry_block, ]

    while len(blocks) > 0:

      block = blocks.pop(0)

      if block in done:
        continue

      done.append(block)

      yield block

      for block in block.jump_to:
        if block not in done:
          if block in blocks:
            # re-add at the end
            blocks.remove(block)
          blocks.append(block)

    return

  def simplify_expressions(self, expr):
    """ combine expressions until they cannot be combined any more. return the new expression. """
    return filters.simplify_expressions.run(expr, deep=True)

  def simplify_statement(self, stmt):
    """ find any expression present in a statement and simplify them. if the statement
        has other statements nested (as is the case for if-then, while, etc), then
        sub-statements are also processed. """

    # simplify sub-statements
    for _stmt in stmt.statements:
      self.simplify_statement(_stmt)

    filters.simplify_expressions.run(stmt.expr, deep=True)

    return stmt

  def make_statement(self, item):
    """ always return a statement from an expression or a statement. """

    if isinstance(item, statement_t):
      stmt = item
    elif isinstance(item, expr_t):
      stmt = statement_t(item)
    else:
      raise RuntimeError("don't know how to make a statement with %s" % (repr(item), ))

    return stmt

  def transform_ir(self):
    """ transform the program into the intermediate representation. """

    for block in self.iterblocks():

      # for all item in the block, process each statement.
      for item in block.items:
        for expr in self.arch.generate_statements(item):

          # upgrade expr to statement if necessary
          stmt = self.make_statement(expr)

          # apply simplification rules to all expressions in this statement
          stmt = self.simplify_statement(stmt)

          block.container.add(stmt)

      # if the block 'falls' without branch instruction into another one, add a goto for clarity
      if block.falls_into:
        block.container.add(goto_t(value_t(block.falls_into.ea, self.arch.address_size)))

    return

  def combine_blocks(self):
    filters.controlflow.run(self)
    return
