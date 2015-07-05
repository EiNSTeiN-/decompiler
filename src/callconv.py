""" Abstracts the logic behind figuring out the arguments to a function call.

http://en.wikipedia.org/wiki/X86_calling_conventions
"""

from expressions import *
import ir.intel
import ssa

__conventions__ = {}

def add_calling_convention(cls):
  __conventions__[cls.__name__] = cls
  return cls

class call_iterator_t(ssa.ssa_contextual_iterator_t):

  def __init__(self, function):
    ssa.ssa_contextual_iterator_t.__init__(self, function, self.is_correct_step)
    self.contexts = []
    return

  def is_correct_step(self, loc):
    return isinstance(loc, assignable_t)

  def is_call(self, expr):
    return isinstance(expr, assign_t) and isinstance(expr.op2, call_t)

  def copy_recursive_context(self, context):
    defined = []
    cur = context
    while cur:
      for _def in reversed(cur.defined):
        defined.append(_def)
      cur = cur.parent
    return list(reversed(defined))

  def statement(self, context, stmt, ):
    if self.is_call(stmt.expr):
      self.contexts.append((self.copy_recursive_context(context), stmt))
    ssa.ssa_contextual_iterator_t.statement(self, context, stmt)
    return

  def __iter__(self):
    self.traverse(ssa.ssa_context_t(self.function.entry_block))
    for ctx, stmt in self.contexts:
      yield ctx, stmt
    return

class convention_t(object):

  def __init__(self, function):
    self.function = function
    return

@add_calling_convention
class live_locations(convention_t):

  def process_live_stack_locations(self, context, call):
    """ find all live stack locations at the top of the stack in this context. """

    # top of stack
    tos = call.stack.copy()
    if not isinstance(tos, sub_t):
      # weird stack?
      return []

    args = []
    while True:
      found = None
      for _def in (context):
        if _def.no_index_eq(deref_t(tos.copy())):
          found = _def
      if not found:
        break
      args.append(found)
      tos.op2.value -= 4

    return args

  def process_live_registers(self, context, stmt):
    """ find all live stack locations at the top of the stack in this context. """

    args = []
    for defined in context:
      if defined.parent_statement is stmt:
        continue
      if type(defined) is regloc_t:
        args.append(defined)

    return args

  def process(self):
    for ctx, stmt in call_iterator_t(self.function):

      args = []
      args += self.process_live_stack_locations(ctx, stmt.expr.op2)
      args += self.process_live_registers(ctx, stmt)

      for arg in args:
        copy = arg.copy(with_definition=True)
        copy.definition = arg
        stmt.expr.op2.params.append(copy)
    return

@add_calling_convention
class systemv_x64_abi_t(convention_t):
  """ SystemV AMD64 ABI

  The following registers are used to pass arguments:
      RDI, RSI, RDX, RCX, R8, R9, XMM0-7
  """

  def process(self, function, ssa_tagger, block, stmt, call):

    # RDI, RSI, RDX, RCX, R8, R9
    which = [ir.intel.RDI, ir.intel.RSI, ir.intel.RDX, ir.intel.RCX, ir.intel.R8, ir.intel.R9]
    regs = []
    for n in which:
      loc = regloc_t(n, function.arch.address_size)
      newloc = ssa_tagger.has_internal_definition(stmt, loc)
      if newloc:
        regs.append(newloc.copy())
      elif ssa_tagger.has_contextual_definition(stmt, loc):
        newloc = self.insert_phi(stmt, loc)
        regs.append(newloc.copy())
      else:
        break

    params = self.make_call_arguments(regs)
    call.params = params

    return

  def make_call_arguments(self, regs):

    if len(regs) == 0:
      return None

    regs = regs[:]

    arglist = regs.pop(-1)
    while len(regs) > 0:
      arglist = comma_t(regs.pop(-1), arglist)

    return arglist

@add_calling_convention
class cdecl(live_locations):

  def process(self):
    for ctx, stmt in call_iterator_t(self.function):
      args = self.process_live_stack_locations(ctx, stmt.expr.op2)
      for arg in args:
        copy = arg.copy(with_definition=True)
        copy.definition = arg
        stmt.expr.op2.params.append(copy)
    return
