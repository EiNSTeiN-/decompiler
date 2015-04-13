
import flow
import ssa
import propagator
from iterators import *

from statements import *
from expressions import *

import callconv

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

class arguments_renamer_t(renamer_t):
  """ rename arguments """

  def __init__(self, dec):
    renamer_t.__init__(self, dec.flow)

    self.dec = dec
    self.ssa_tagger = dec.ssa_tagger

    """ keeps track of the next index """
    self.argn = 0

    """ dict of relations between definition and argument name """
    self.argument_locations = {}
    return

  def is_restored(self, expr):
    for exit, define in self.dec.restored_locations.iteritems():
      if define == expr and exit != define:
        return True
    return False

  def rename_with(self, expr):

    loc = [loc for loc in self.argument_locations.keys() if loc.no_index_eq(expr)]
    if len(loc) == 1:
      argn = self.argument_locations[loc[0]]
    else:
      argn = self.argn
      self.argument_locations[expr.copy()] = argn
      self.argn += 1

    name = 'a%u' % (argn, )
    arg = arg_t(expr.copy(), name)
    return arg

class register_arguments_renamer_t(arguments_renamer_t):

  def should_rename(self, expr):
    if not isinstance(expr, regloc_t):
      return False
    if self.flow.arch.is_stackreg(expr):
      return False

    if expr in self.ssa_tagger.uninitialized:
      restored = self.is_restored(expr)
      if not restored or len(expr.uses) > 0:
        return True

    if isinstance(expr, assignable_t) and  expr.definition:
      if expr.definition in self.ssa_tagger.uninitialized:
        return True

    for loc in self.argument_locations:
      if loc.no_index_eq(expr):
        return True

    return False

class stack_arguments_renamer_t(arguments_renamer_t):

  def should_rename(self, expr):
    if not isinstance(expr, deref_t):
      return False
    if not self.flow.arch.is_stackvar(expr.op):
      return False
    if isinstance(expr.op, sub_t):
      return False

    if expr in self.ssa_tagger.uninitialized:
      restored = self.is_restored(expr)
      if not restored or len(expr.uses) > 0:
        return True

    if isinstance(expr, assignable_t) and  expr.definition:
      if expr.definition in self.ssa_tagger.uninitialized:
        return True

    for loc in self.argument_locations:
      if loc.no_index_eq(expr):
        return True

    return False

class stack_variables_renamer_t(renamer_t):
  """ rename stack locations """

  def __init__(self, flow):
    renamer_t.__init__(self, flow)

    """ keeps track of the next index """
    self.varn = 0

    """ dict of relations between stack location and variable name """
    self.stack_locations = {}
    return

  def should_rename(self, expr):
    if self.flow.arch.is_stackreg(expr) and not expr.is_def:
      return True
    if self.flow.arch.is_stackvar(expr):
      return isinstance(expr, add_t)

    if isinstance(expr, deref_t):
      if self.flow.arch.is_stackreg(expr.op):
        return True
      if self.flow.arch.is_stackvar(expr.op):
        return isinstance(expr.op, sub_t)

    return False

  def find_stack_location(self, op):
    if isinstance(op, deref_t):
      # continue with just the content of the dereference.
      op = op[0]

    if self.flow.arch.is_stackreg(op):
      # naked register, like 'esp'
      return 0

    if isinstance(op, sub_t):
      # 'esp - 4'
      return op.op2.value

    assert 'weird stack location?'

  def rename_with(self, op):
    loc = self.find_stack_location(op)

    var = var_t(loc)

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
    if isinstance(use.parent, theta_t) or \
        isinstance(value, theta_t) or \
        not isinstance(value, replaceable_t):
      return
    if self.flow.arch.is_stackreg(defn) or \
        self.is_stack_location(value):
      return value

  def is_stack_location(self, expr):
    return self.flow.arch.is_stackreg(expr) or \
      self.flow.arch.is_stackvar(expr)

class registers_propagator_t(propagator.propagator_t):
  def replace_with(self, defn, value, use):
    if isinstance(use, regloc_t):
      return value

class pruner_t(object):

  def __init__(self, flow):
    self.flow = flow
    return

  def is_prunable(self, stmt):
    return False

  def remove(self, stmt):
    for expr in stmt.expr.iteroperands():
      if isinstance(expr, assignable_t):
        if expr.definition and expr in expr.definition.uses:
          expr.definition.uses.remove(expr)
    stmt.remove()
    return

  def prune(self):
    while True:
      pruned = False
      for stmt in statement_iterator_t(self.flow):
        if not self.is_prunable(stmt):
          continue
        pruned = True
        self.remove(stmt)
      if not pruned:
        break
    return

class unused_registers_pruner_t(pruner_t):

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

class restored_locations_pruner_t(pruner_t):

  def __init__(self, dec):
    pruner_t.__init__(self, dec.flow)
    self.dec = dec
    return

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if stmt.expr.op2 not in self.dec.restored_locations.values():
      return False
    return len(stmt.expr.op1.uses) == 0

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
class step_ssa_removed(step_t):
  description = 'Function is transformed out of ssa form'
class step_arguments_renamed(step_t):
  description = 'Arguments are renamed'
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

  def adjust_returns(self):
    for stmt in statement_iterator_t(self.flow):
      if isinstance(stmt, return_t):
        if not isinstance(stmt.expr, assignable_t):
          return
        if stmt.expr.definition is not None:
          # early return if one path is initialized
          return
    for stmt in statement_iterator_t(self.flow):
      if isinstance(stmt, return_t):
        stmt.expr = None
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
    self.spoiled_locations = self.ssa_tagger.spoiled_locations()
    self.adjust_returns()
    yield self.set_step(step_ssa_form_derefs())

    self.register_arguments_renamer = register_arguments_renamer_t(self)
    self.register_arguments_renamer.rename()
    self.stack_arguments_renamer = stack_arguments_renamer_t(self)
    self.stack_arguments_renamer.rename()
    self.ssa_tagger.tag_arguments()
    yield self.set_step(step_arguments_renamed())

    # todo: properly find function call arguments.
    #conv = callconv.systemv_x64_abi()
    #self.solve_call_parameters(t, conv)
    #yield self.set_step(step_calls())

    # prune unused registers
    self.pruner = unused_registers_pruner_t(self.flow)
    self.pruner.prune()
    # prune assignments for restored locations
    self.pruner = restored_locations_pruner_t(self)
    self.pruner.prune()
    yield self.set_step(step_pruned())

    self.stack_variables_renamer = stack_variables_renamer_t(self.flow)
    self.stack_variables_renamer.rename()
    self.ssa_tagger.tag_variables()
    yield self.set_step(step_stack_renamed())

    # propagate assignments to local variables.
    self.propagator = registers_propagator_t(self.flow)
    self.propagator.propagate()
    yield self.set_step(step_propagated())

    # todo: rename local variables
    #yield self.set_step(step_locals_renamed())

    # todo: remove unused definitions
    #yield self.set_step(step_pruned())

    # get us out of ssa form.
    self.ssa_tagger.remove_ssa_form()
    yield self.set_step(step_ssa_removed())

    # after everything is done, we can combine blocks!
    self.flow.combine_blocks()
    yield self.set_step(step_combined())

    yield self.set_step(step_decompiled())
    return

