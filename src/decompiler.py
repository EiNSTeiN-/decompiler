
import flow
import ssa
import propagator
from iterators import *

from statements import *
from expressions import *

import filters.simplify_expressions
import callconv

RENAME_STACK_LOCATIONS = 1
RENAME_REGISTERS = 2

class renamer(object):
  """ this class takes care of renaming variables. stack locations and
  registers are wrapped in var_t and arg_t if they are respectively
  local variables or function arguments.
  """

  varn = 0
  argn = 0

  def __init__(self, flow, flags):
    self.flow = flow
    self.flags = flags

    self.reg_arguments = {}
    self.reg_variables = {}
    #~ self.stack_arguments = {}
    self.stack_variables = {}

    return

  def stack_variable(self, expr):

    assert self.flow.arch.is_stackvar(expr)

    if type(expr) == regloc_t and self.flow.arch.is_stackreg(expr):
      index = 0
    else:
      index = -(expr.op2.value)

    if index in self.stack_variables:
      return self.stack_variables[index].copy()

    var = var_t(expr.copy())
    var.name = 's%u' % (renamer.varn, )
    renamer.varn += 1

    self.stack_variables[index] = var

    return var

  def reg_variable(self, expr):

    assert type(expr) == regloc_t

    for reg in self.reg_variables:
      if reg == expr:
        return self.reg_variables[reg].copy()

    var = var_t(expr)
    self.reg_variables[expr] = var

    var.name = 'v%u' % (renamer.varn, )
    renamer.varn += 1

    return var

  def reg_argument(self, expr):

    assert type(expr) == regloc_t

    for reg in self.reg_arguments:
      if reg == expr:
        return self.reg_arguments[reg].copy()

    arg = arg_t(expr)
    self.reg_arguments[expr] = arg

    name = 'a%u' % (renamer.argn, )
    arg.name = name
    renamer.argn += 1

    return arg

  def rename_variables_callback(self, block, container, stmt, expr):

    if self.flags & RENAME_STACK_LOCATIONS:
      # stack variable value
      if type(expr) == deref_t and self.flow.arch.is_stackvar(expr.op):
        var = self.stack_variable(expr.op.copy())
        expr.replace(var)
        return
      # stack variable address
      if self.flow.arch.is_stackvar(expr):
        var = self.stack_variable(expr.copy())
        expr.replace(address_t(var))
        return

    if self.flags & RENAME_REGISTERS:
      if type(expr) == regloc_t and expr in self.fct_arguments:
        arg = self.reg_argument(expr.copy())
        expr.replace(arg)
        return
      if type(expr) == regloc_t:
        var = self.reg_variable(expr.copy())
        expr.replace(var)
        return
    return

  def wrap_variables(self):
      iter = flow_iterator(self.flow, expression_iterator = self.rename_variables_callback)
      iter.do()
      return

class renamer_t(object):
  """ rename locations """

  def __init__(self, flow):
    self.flow = flow
    return

  def rename(self):
    for op in operand_iterator_t(self.flow):
      if self.should_rename(op):
        new = self.rename_with(op)
        op.replace(new)
    return

class stack_renamer_t(renamer_t):
  """ rename stack locations """

  def __init__(self, flow):
    renamer_t.__init__(self, flow)

    """ keeps track of the next index """
    self.varn = 0

    """ dict of relations between stack location and variable name """
    self.stack_locations = {}
    return

  def should_rename(self, op):
    return self.flow.arch.is_stackreg(op) or \
      self.flow.arch.is_stackvar(op) or \
      (isinstance(op, deref_t) and self.flow.arch.is_stackreg(op[0])) or \
      (isinstance(op, deref_t) and self.flow.arch.is_stackvar(op[0]))

  def find_stack_location(self, op):
    if isinstance(op, deref_t):
      # continue with just the content of the dereference.
      op = op[0]

    if self.flow.arch.is_stackreg(op):
      # naked register, like 'esp'
      return 0

    if type(op) in (sub_t, add_t):
      # 'esp + 4' or 'esp - 4'
      return op.op2.value

    assert 'weird stack location?'

  def rename_with(self, op):
    var = var_t(op.copy())
    if isinstance(op, deref_t) and op.is_def:
      var.index = op.index

    loc = self.find_stack_location(op)

    if loc in self.stack_locations.keys():
      var_index = self.stack_locations[loc]
    else:
      var_index = self.varn
      self.stack_locations[loc] = var_index
      self.varn += 1
    var.name = 's%u' % (var_index, )

    if isinstance(op, deref_t):
      return var

    return address_t(var)

class stack_propagator_t(propagator.propagator_t):
  def replace_with(self, defn, value, use):
    if self.flow.arch.is_stackreg(defn) and \
        not isinstance(use.parent, theta_t) and \
        not isinstance(value, theta_t) and \
        isinstance(value, replaceable_t):
      return value

class pruner_t(object):

  def __init__(self, flow):
    self.flow = flow
    return

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if isinstance(stmt.expr.op2, call_t):
      return False
    if not isinstance(stmt.expr.op1, assignable_t):
      return False
    if not isinstance(stmt.expr.op1, regloc_t):
      return False
    if stmt.expr.op1.index is None:
      return False
    if len(stmt.expr.op1.uses) > 0:
      return False
    return True

  def prune(self):
    for stmt in statement_iterator_t(self.flow):
      if not self.is_prunable(stmt):
        continue
      stmt.remove()
    return

class step_t(object):
  description = None
class step_nothing_done(step_t):
  description = 'Nothing done yet'
class step_basic_blocks(step_t):
  description = 'Basic block information ready'
class step_ir_form(step_t):
  description = 'Intermediate form is ready'
class step_ssa_form_registers(step_t):
  description = 'Static single assignment form (registers)'
class step_ssa_form_derefs(step_t):
  description = 'Static single assignment form (dereferences)'
class step_stack_propagated(step_t):
  description = 'Stack variable is propagated'
class step_stack_renamed(step_t):
  description = 'Stack locations and registers are renamed'
class step_pruned(step_t):
  description = 'Dead assignments pruned'
class step_calls(step_t):
  description = 'Call information found'
class step_propagated(step_t):
  description = 'Assignments have been propagated'
class step_locals_renamed(step_t):
  description = 'Local variable locations and registers are renamed'
class step_combined(step_t):
  description = 'Basic blocks are reassembled'
class step_decompiled(step_t):
  description = 'Stack locations and registers are renamed'

class decompiler_t(object):

  def __init__(self, disasm, ea):
    self.ea = ea
    self.disasm = disasm

    self.step_generator = self.steps()
    self.current_step = None

    # ssa_tagger_t object
    self.ssa_tagger = None

    self.stack_indices = {}
    self.var_n = 0

    self.steps = []

    return

  def set_step(self, step):
    self.current_step = step
    self.steps.append(step)
    return self.current_step

  def step_until(self, stop_step):
    """ decompile until the given step. """
    for step in self.step_generator:
      if step.__class__ == stop_step:
        break
    return

  def solve_call_parameters(self, ssa_tagger, conv):
    for ea, block in self.flow.blocks.items():
      for stmt in block.container:
        for expr in stmt.expressions:
          for op in expr.iteroperands():
            if type(op) == call_t:
              conv.process(self.flow, ssa_tagger, block, stmt, op)
    return

  def steps(self):
    """ this is a generator function which yeilds the last decompilation step
        which was performed. the caller can then observe the function flow. """

    self.flow = flow.flow_t(self.ea, self.disasm)
    yield self.set_step(step_nothing_done())

    self.flow.find_control_flow()
    yield self.set_step(step_basic_blocks())

    self.flow.transform_ir()
    yield self.set_step(step_ir_form())

    self.ssa_tagger = ssa.ssa_tagger_t(self.flow)
    self.ssa_tagger.tag_registers()
    yield self.set_step(step_ssa_form_registers())

    self.propagator = stack_propagator_t(self.flow)
    self.propagator.propagate()
    yield self.set_step(step_stack_propagated())

    self.ssa_tagger.tag_derefs()
    self.restored_locations = self.ssa_tagger.restored_locations()
    yield self.set_step(step_ssa_form_derefs())

    self.pruner = pruner_t(self.flow)
    self.pruner.prune()
    yield self.set_step(step_pruned())

    self.stack_renamer = stack_renamer_t(self.flow)
    self.stack_renamer.rename()
    yield self.set_step(step_stack_renamed())

    #conv = callconv.systemv_x64_abi()
    #self.solve_call_parameters(t, conv)
    #yield self.set_step(step_calls())

    #self.find_stack_locations()
    #self.rename_register_locations()
    #yield self.set_step(step_renamed())


    #~ # This propagates special flags.
    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ # re-propagate after gluing pre/post increments
    #~ #s = simplifier(self.flow, COLLECT_ALL)
    #~ #s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_ANY | PROPAGATE_SINGLE_USES)

    #yield self.set_step(step_propagated())



    #~ # remove special flags (eflags) definitions that are not used, just for clarity
    #~ s = simplifier(self.flow, COLLECT_FLAGS)
    #~ s.remove_unused_definitions()

    #~ s = simplifier(self.flow, COLLECT_REGISTERS)
    #~ s.remove_unused_definitions()

    #~ # eliminate restored registers. during this pass, the simplifier also collects
    #~ # stack variables because registers may be preserved on the stack.
    #~ s = simplifier(self.flow, COLLECT_REGISTERS | COLLECT_VARIABLES)
    #~ s.process_restores()
    #~ # ONLY after processing restores can we do this; any variable which is assigned
    #~ # and never used again is removed as dead code.
    #~ s = simplifier(self.flow, COLLECT_REGISTERS)
    #~ s.remove_unused_definitions()

    #yield self.set_step(step_pruned())



    #~ # after everything is done, we can combine blocks!
    #~ self.flow.combine_blocks()
    #yield self.set_step(step_combined())


    #yield self.set_step(step_decompiled())
    return

