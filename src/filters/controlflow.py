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

__block_filters__ = [] # filters that are applied to a flow block
__container_filters__ = [] # filters that are applied to a container (i.e. inside a then-branch of an if_t)

def block_filter(func):
  __block_filters__.append(func)

def container_filter(func):
  __container_filters__.append(func)

def jump_to(flow, block):
  """ return a list of blocks where `block` leads to, based on gotos in `block` """
  to = []
  for stmt in iterators.statement_iterator_t(flow):
    if stmt.container.block != block:
      continue
    if type(stmt) == goto_t:
      to.append(flow.blocks[stmt.expr.value])
    elif type(stmt) == branch_t:
      to.append(flow.blocks[stmt.true.value])
      to.append(flow.blocks[stmt.false.value])
  return to

def jump_from(flow, block):
  """ return a list of blocks where `block` leads to, based on gotos in `block` """
  src = []
  for stmt in iterators.statement_iterator_t(flow):
    if type(stmt) == goto_t:
      if stmt.expr.value == block.ea:
        src.append(stmt.container.block)
    elif type(stmt) == branch_t:
      if stmt.true.value == block.ea:
        src.append(stmt.container.block)
      if stmt.false.value == block.ea:
        src.append(stmt.container.block)
  return src

def is_branch_block(block):
  """ return True if the last statement in a block is a branch statement. """
  return len(block.container) >= 1 and type(block.container[-1]) == branch_t

def invert_goto_condition(stmt):
  """ invert the goto at the end of a block for the goto in
      the if_t preceding it """

  stmt.true.value, stmt.false.value = stmt.false.value, stmt.true.value

  stmt.expr = b_not_t(stmt.expr.pluck())
  simplify_expressions.run(stmt.expr, deep=True)

  return

def combine_branch_blocks(flow, this, next):
  """ combine two if_t that jump to the same destination into a boolean or expression. """

  left = [this.container[-1].true.value, this.container[-1].false.value]
  right = [next.container[-1].true.value, next.container[-1].false.value]

  dest = list(set(left).intersection(set(right)))

  if len(dest) != 1:
    return False

  # both blocks have one jump in common.
  dest = dest[0]

  if this.container[-1].false.value == dest:
    invert_goto_condition(this.container[-1])

  if next.container[-1].false.value == dest:
    invert_goto_condition(next.container[-1])

  common = flow.blocks[dest]
  exit = flow.blocks[next.container[-1].false.value]

  if exit == this:
    cls = b_and_t
  else:
    cls = b_or_t

  stmt = this.container[-1]
  stmt.expr = cls(stmt.expr.copy(), next.container[-1].expr.copy())
  simplify_expressions.run(stmt.expr, deep=True)

  this.container[-1].false = next.container[-1].false

  flow.blocks.pop(next.ea)

  return True

@block_filter
def combine_conditions(flow, block):
  """ combine two ifs into a boolean or (||) or a boolean and (&&). """

  if not is_branch_block(block):
    return False

  for next in jump_to(flow, block):
    if not is_branch_block(next) or len(next.container) != 1:
      continue

    if combine_branch_blocks(flow, block, next):
      return True

  return False

def switch_goto_if_needed(block, dstblock):
  """ if the last item at the end of 'block' is a goto to dstblock, do nothing,
      otherwise invert that goto with the one in the if_t in the next-to-last
      position. """

  container = block.container
  assert type(container[-1]) == goto_t

  if container[-1].expr.value == dstblock.ea:
    return

  if len(container) < 2:
    return

  assert type(container[-2]) == if_t
  assert len(container[-2].then_expr) == 1
  assert type(container[-2].then_expr[0]) == goto_t
  assert container[-2].then_expr[0].expr.value == dstblock.ea

  # invert goto_t destinations
  container[-1].expr.value, container[-2].then_expr[0].expr.value = \
    container[-2].then_expr[0].expr.value, container[-1].expr.value

  container[-2].expr = b_not_t(container[-2].expr.copy())
  simplify_expressions.run(container[-2].expr, deep=True)

  return

def change_loop_continues(flow, parent_block, container, first_block, exit_block):
  """ if 'block' ends with a goto_t that leads back to first_block,
      then change it into a continue_t. """

  for stmt in container.statements:
    if type(stmt) == goto_t:
      if parent_block == first_block and stmt == parent_block.container[-1]:
        continue
      if flow.get_block(stmt) == first_block:
        idx = stmt.container.index(stmt)
        container = stmt.container
        flow.remove_goto(parent_block, stmt)
        container.insert(idx, continue_t())
    else:
      change_loop_continues(flow, parent_block, stmt, first_block, exit_block)
  return

def convert_break_in_container(flow, block, container, goto):

  for stmt in container:

    if type(stmt) in (while_t, do_while_t):
      # cannot break from inner while to outer while...
      continue

    elif type(stmt) == if_t:
      if convert_break_in_container(flow, block, stmt.then_expr, goto):
        return True

      if stmt.else_expr:
        if convert_break_in_container(flow, block, stmt.else_expr, goto):
          return True

    elif type(stmt) == goto_t and stmt.expr == goto.expr:

      idx = container.index(stmt)
      flow.remove_goto(block, stmt)

      container.insert(idx, break_t())

      return True

  return False

@container_filter
def convert_break(flow, block, container):
  """ in a while_t followed by a goto_t, we can safely replace any instance
      of the same goto_t from inside the loop by a break_t.
  """

  for i in range(len(container)-1):
    stmt = container[i]
    goto = container[i+1]

    if type(stmt) in (while_t, do_while_t) and type(goto) == goto_t:
      return convert_break_in_container(flow, block, stmt.loop_container, goto)

    return False

@block_filter
def convert_infinite_while(flow, block):
  """ when the last statement in a container is a jump to itself. """

  if len(block.container) == 0:
    return False

  stmt = block.container[-1]
  if type(stmt) == goto_t and stmt.expr.value == block.ea:
    stmt.remove()
    new = while_t(value_t(1, 1), container_t(block, block.container[:]))
    block.container[:] = []
    block.container.add(new)

  return False

@block_filter
def convert_while_block(flow, block):
  """ first item in a block is a if(), where the last statement in
      the if() is a goto to the beginning of the block. """

  if len(block.container) == 0:
    return False

  if type(block.container[0]) != if_t:
    return False

  _if = block.container[0]

  if _if.else_expr is not None or \
      type(_if.then_expr[-1]) != goto_t or \
      _if.then_expr[-1].expr.value != block.ea:
    return False

  newblock = while_t(_if.expr.pluck(), container_t(block, _if.then_expr[:-1]))
  simplify_expressions.run(newblock.expr, deep=True)
  block.container.insert(_if.index(), newblock)
  _if.remove()
  return True

@block_filter
def convert_do_while_block(flow, block):
  """ last item in a block is a branch going to the beginning of the block. """

  if len(block.container) == 0:
    return False

  if type(block.container[-1]) != branch_t:
    return False

  branch = block.container[-1]
  if branch.true.value != block.ea:
    return False

  newblock = do_while_t(branch.expr.pluck(), container_t(block, block.container[:-1]))
  block.container[:] = []
  simplify_expressions.run(newblock.expr, deep=True)
  block.container.insert(0, newblock)
  block.container.insert(1, goto_t(branch.false))
  return True

@container_filter
def combine_noreturns(flow, block, container):
  """ if the last call before a goto_t is a noreturn call,
      then remove the goto_t (which is incorrect anyway). """
  # TODO: the flow code shouldn't put a goto there in the first place.

  if len(container) < 2 or type(container[-1]) != goto_t:
    return False

  goto = container[-1]
  if type(goto.expr) != value_t or type(container[-2]) != statement_t:
    return False

  dst_block = flow.blocks[goto.expr.value]

  if type(container[-2].expr) == call_t:
    call = container[-2].expr
  elif type(container[-2].expr) == assign_t and type(container[-2].expr.op2) == call_t:
    call = container[-2].expr.op2
  else:
    return False

  if type(call.fct) != value_t:
    return False

  if flow.arch.function_does_return(call.fct.value):
    return False

  container.remove(goto)

  return True

@container_filter
def combine_block_tail(flow, block, container):
  """ combine goto's with their destination, if the destination has only one path that reaches it """

  if len(container) < 1:
    return False

  last_stmt = container[-1]

  if type(last_stmt) != goto_t or type(last_stmt.expr) != value_t:
    return False

  dst_ea = last_stmt.expr.value
  dst_block = flow.blocks[dst_ea]

  # check if there is only one jump destination, with the exception of jumps to itself (loops)
  if len(jump_from(flow, dst_block)) != 1:
    return False

  # pop goto
  container.pop()

  # extend cur. container with dest container's content
  container.extend(dst_block.container[:])
  flow.blocks.pop(dst_block.ea)

  return True

@container_filter
def combine_else_tails(flow, block, container):
  """ if a block contains an if_t whose then-side ends with the same
      goto_t as the block itself, then merge all expressions at the
      end of the block into the else-side of the if_t.

      if (...) { abc; goto foo; }
      xyz;
      goto foo;

      becomes

      if (...) { abc; }
      else { xyz; }
      goto foo;

      """

  for i in range(len(container)):
    stmt = container[i]

    while True:
      if type(stmt) == if_t and len(stmt.then_expr) >= 1 and \
            type(container[-1]) == goto_t and type(stmt.then_expr[-1]) == goto_t and \
            container[-1] == stmt.then_expr[-1]:

        goto = stmt.then_expr.pop(-1)
        dstblock = flow.blocks[goto.expr.value]

        stmts = container[i+1:-1]
        container[i+1:-1] = []
        stmt.else_expr = container_t(block, stmts)

        return True

      if type(stmt) == if_t and stmt.else_expr and len(stmt.else_expr) == 1 and \
            type(stmt.else_expr[0]) == if_t:
        stmt = stmt.else_expr[0]
        continue

      break

  return False

@container_filter
def invert_empty_if_block(flow, block, container):
  """ invert then and else side if then-side is empty """

  for stmt in container:
    if type(stmt) == if_t and stmt.else_expr is not None and len(stmt.then_expr) == 0:
      stmt.then_expr = stmt.else_expr
      stmt.expr = b_not_t(stmt.expr.copy())
      stmt.else_expr = None

      simplify_expressions.run(stmt.expr, deep=True)

      return True

  return False

@container_filter
def remove_empty_if_block(flow, block, container):
  """ remove if_t altogether if it contains no statements at all """

  for stmt in container:
    if type(stmt) == if_t and stmt.else_expr is None and len(stmt.then_expr) == 0:
      container.remove(stmt)
      return True

  return False

@container_filter
def beautify_elseif(flow, block, container):
  """ if we have an if_t as only statement in the then-side of a parent
      if_t, and the parent if_t has an else-side which doesn't contain
      an if_t as only statement (to avoid infinite loops), then we can
      safely invert the two sides of the parent if_t so that it will be
      displayed in the more natural 'if(...) { } else if(...) {}' form.
  """

  for stmt in container:
    if type(stmt) == if_t and stmt.else_expr and \
          len(stmt.then_expr) == 1 and type(stmt.then_expr[0]) == if_t and \
          not (len(stmt.else_expr) == 1 and type(stmt.else_expr[0]) == if_t): \

      stmt.then_expr, stmt.else_expr = stmt.else_expr, stmt.then_expr

      stmt.expr = b_not_t(stmt.expr.copy())
      simplify_expressions.run(stmt.expr, deep=True)

      return True

  return False

@container_filter
def combine_simple_if_branch(flow, block, container):
  """ very simple if() form. """

  for stmt in container:
    if type(stmt) != branch_t:
      continue
    true_block = flow.blocks[stmt.true.value]
    false_block = flow.blocks[stmt.false.value]

    if type(true_block.container[-1]) == goto_t and \
        true_block.container[-1].expr.value == stmt.false.value and \
        len(jump_from(flow, true_block)) == 1:
      newblock = if_t(stmt.expr.pluck(), container_t(block, true_block.container[:-1]))
      simplify_expressions.run(newblock.expr, deep=True)
      block.container.insert(stmt.index(), newblock)
      block.container.insert(stmt.index(), goto_t(stmt.false))
      stmt.remove()
      flow.blocks.pop(true_block.ea)
      return True

    if type(false_block.container[-1]) == goto_t and \
        false_block.container[-1].expr.value == stmt.true.value and \
        len(jump_from(flow, false_block)) == 1:
      newblock = if_t(b_not_t(stmt.expr.pluck()), container_t(block, false_block.container[:-1]))
      simplify_expressions.run(newblock.expr, deep=True)
      block.container.insert(stmt.index(), newblock)
      block.container.insert(stmt.index(), goto_t(stmt.true))
      stmt.remove()
      flow.blocks.pop(false_block.ea)
      return True

  return False

@container_filter
def combine_if_else_branch(flow, block, container):
  """ very simple if-else form. """

  for stmt in container:
    if type(stmt) != branch_t:
      continue
    true_block = flow.blocks[stmt.true.value]
    false_block = flow.blocks[stmt.false.value]

    if type(true_block.container[-1]) == goto_t and \
        type(false_block.container[-1]) == goto_t and \
        true_block.container[-1].expr.value == false_block.container[-1].expr.value and \
        len(jump_from(flow, true_block)) == 1 and \
        len(jump_from(flow, false_block)) == 1:
      exit_block = flow.blocks[true_block.container[-1].expr.value]
      then = container_t(block, true_block.container[:-1])
      _else = container_t(block, false_block.container[:-1])
      newblock = if_t(stmt.expr.pluck(), then, _else)
      block.container.insert(stmt.index(), newblock)
      block.container.insert(stmt.index(), goto_t(true_block.container[-1].expr))
      stmt.remove()
      flow.blocks.pop(true_block.ea)
      flow.blocks.pop(false_block.ea)
      return True

  return False

@container_filter
def combine_if_body(flow, block, container):
  """ combine block that can be accessed from only one if() branch. """

  for stmt in container:
    if type(stmt) != branch_t:
      continue

    true_block = flow.blocks[stmt.true.value]
    if type(true_block.container[-1]) == goto_t and \
        len(jump_from(flow, true_block)) == 1:
      newblock = if_t(stmt.expr.pluck(), container_t(block, true_block.container[:]))
      simplify_expressions.run(newblock.expr, deep=True)
      block.container.insert(stmt.index(), newblock)
      block.container.insert(stmt.index(), goto_t(stmt.false))

      stmt.remove()
      flow.blocks.pop(stmt.true.value)

      return True

  return False

def combine_container_run(flow, block, container):
  """ process all possible combinations for all containers. """

    # first deal with possible nested containers.
  for stmt in container:
    if type(stmt) == if_t:
      if combine_container_run(flow, block, stmt.then_expr):
        return True
      if stmt.else_expr:
        if combine_container_run(flow, block, stmt.else_expr):
          return True
    elif type(stmt) in (while_t, do_while_t):
      if combine_container_run(flow, block, stmt.loop_container):
        return True

  # apply filters to this container last.
  for filter in __container_filters__:
    if filter(flow, block, container):
      #~ print '---filter---'
      #~ print str(flow)
      #~ print '---filter---'
      return True

  return False

def combine_container(flow, block):
  """ process all possible combinations for the top-level container of a block """
  return combine_container_run(flow, block, block.container)
__block_filters__.append(combine_container)

def once(flow):
  """ do one combination pass until a single combination is performed. """
  for filter in __block_filters__:
    for block in flow.blocks.values():
      if filter(flow, block):
        return True
  return False

def run(flow):
  """ combine until no more combinations can be applied. """
  while True:
    if not once(flow):
      break
  return
