""" Abstracts the logic behind figuring out the arguments to a function call.

http://en.wikipedia.org/wiki/X86_calling_conventions
"""

from expressions import *
import ir.intel
import ssa

__conventions__ = {}

def add_calling_convention(cls):
  __conventions__[cls.__name__] = cls

class call_iterator_t(ssa.ssa_tagger_t):

  def __init__(self, flow):
    ssa.ssa_tagger_t.__init__(self, flow)

    self.contexts = []
    return

  def is_correct_step(self, loc):
    return isinstance(loc, assignable_t)

  def tag_tethas(self, context, block):
    return

  def tag_uses(self, context, block, expr):
    return

  def is_call(self, expr):
    return isinstance(expr, assign_t) and isinstance(expr.op2, call_t)

  def statement(self, context, stmt):
    if self.is_call(stmt.expr):
      self.contexts.append((context.copy(), stmt))
    return

  def __iter__(self):
    self.tag_block(ssa.ssa_context_t(), self.flow.entry_block)
    for ctx, stmt in self.contexts:
      yield ctx, stmt
    return

class convention_t(object):

  def __init__(self, flow):
    self.flow = flow
    return

@add_calling_convention
class live_locations(convention_t):

  def process_live_stack_locations(self, context, call):
    """ find all live stack locations at the top of the stack in this context. """

    # top of stack
    tos = call.stack.copy()
    if not isinstance(tos, sub_t):
      # weird stack?
      return

    args = []
    while True:
      defn = context.get_definition(deref_t(tos.copy()))
      if not defn:
        break
      args.append(defn)
      tos.op2.value -= 4

    return args

  def process(self):
    for ctx, stmt in call_iterator_t(self.flow):

      #for defined in ctx.defined:
      #  if stmt.expr.op1 is defined.loc:
      #    # this is the retval of this call.
      #    continue
      #  print '   ', repr(defined.loc)

      args = self.process_live_stack_locations(ctx, stmt.expr.op2)
      if not args:
        continue

      for arg in args:
        stmt.expr.op2.append(arg.copy(with_definition=True))
      pass
    return

@add_calling_convention
class systemv_x64_abi_t(convention_t):
  """ SystemV AMD64 ABI

  The following registers are used to pass arguments:
      RDI, RSI, RDX, RCX, R8, R9, XMM0-7
  """

  def process(self, flow, ssa_tagger, block, stmt, call):

    # RDI, RSI, RDX, RCX, R8, R9
    which = [ir.intel.RDI, ir.intel.RSI, ir.intel.RDX, ir.intel.RCX, ir.intel.R8, ir.intel.R9]
    regs = []
    for n in which:
      loc = regloc_t(n, flow.arch.address_size)
      print repr(loc)
      newloc = ssa_tagger.has_internal_definition(stmt, loc)
      if newloc:
        regs.append(newloc.copy())
      elif ssa_tagger.has_contextual_definition(stmt, loc):
        newloc = self.insert_theta(stmt, loc)
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
