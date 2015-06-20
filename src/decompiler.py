
import graph
import ssa
import propagator
from iterators import *
import pruner

from statements import *
from expressions import *

import filters.controlflow
import callconv

class renamer_t(object):
  """ rename locations """

  def __init__(self, function):
    self.function = function
    return

  def rename(self):
    for op in operand_iterator_t(self.function, filter=self.should_rename):
      new = self.rename_with(op)
      op.replace(new)
      op.unlink()
    # clear out phi statements with operands that do not have indexes anymore.
    for phi in operand_iterator_t(self.function, klass=phi_t):
      for op in list(phi.operands):
        if op.index is None:
          op.unlink()
          phi.remove(op)
    for stmt in statement_iterator_t(self.function):
      if isinstance(stmt.expr, assign_t) and isinstance(stmt.expr.op2, phi_t) and len(stmt.expr.op2) == 0:
        stmt.expr.unlink()
        stmt.remove()
    return

class arguments_renamer_t(renamer_t):
  """ rename arguments """

  def __init__(self, dec):
    renamer_t.__init__(self, dec.function)

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
      self.argument_locations[expr] = argn
      self.argn += 1

    name = 'a%u' % (argn, )
    arg = arg_t(expr.copy(), name)
    return arg

class register_arguments_renamer_t(arguments_renamer_t):

  def should_rename(self, expr):
    if not isinstance(expr, regloc_t):
      return False
    if self.function.arch.is_stackreg(expr):
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
    if not self.function.arch.is_stackvar(expr.op):
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

  def __init__(self, function):
    renamer_t.__init__(self, function)

    """ keeps track of the next index """
    self.varn = 0

    """ dict of relations between stack location and variable name """
    self.stack_locations = {}
    return

  def should_rename(self, expr):
    if self.function.arch.is_stackreg(expr) and not expr.is_def:
      return True
    if self.function.arch.is_stackvar(expr):
      return isinstance(expr, add_t)

    if isinstance(expr, deref_t):
      if self.function.arch.is_stackreg(expr.op):
        return True
      if self.function.arch.is_stackvar(expr.op):
        return isinstance(expr.op, sub_t)

    return False

  def find_stack_location(self, op):
    if isinstance(op, deref_t):
      # continue with just the content of the dereference.
      op = op[0]

    if self.function.arch.is_stackreg(op):
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
    if isinstance(use.parent, phi_t) or \
        isinstance(value, phi_t) or \
        not isinstance(value, replaceable_t):
      return
    if self.function.arch.is_stackreg(defn) or \
        self.is_stack_location(value):
      return value

  def is_stack_location(self, expr):
    return self.function.arch.is_stackreg(expr) or \
      self.function.arch.is_stackvar(expr)

class registers_propagator_t(propagator.propagator_t):
  def replace_with(self, defn, value, use):
    if isinstance(use, regloc_t) and not isinstance(use.parent, phi_t):
      return value

class call_arguments_propagator_t(propagator.propagator_t):
  def replace_with(self, defn, value, use):
    if len(defn.uses) > 1:
      return
    if isinstance(use.parent, params_t):
      return value

class function_block_t(object):
  def __init__(self, function, node):
    self.function = function
    self.node = node
    self.ea = node.ea
    self.container = container_t(self, [stmt.copy() for stmt in node.statements])
    return

  def __repr__(self):
    return '<%s %x>' % (self.__class__.__name__, self.ea)

  @property
  def jump_to_ea(self):
    """ generates a list of address where `block` leads to, based on gotos and branches in `block` """
    for stmt in statement_iterator_t(self.function):
      if stmt.container.block != self:
        continue
      if type(stmt) == goto_t and stmt.is_known():
        yield stmt.expr.value
      elif type(stmt) == branch_t:
        yield stmt.true.value
        yield stmt.false.value
    return

  @property
  def jump_to(self):
    """ return a list of blocks where `block` leads to, based on gotos in `block` """
    return [self.function.blocks[ea] for ea in self.jump_to_ea]

  @property
  def jump_from_ea(self):
    """ return a list of blocks where `block` leads to, based on gotos in `block` """
    for stmt in statement_iterator_t(self.function):
      if type(stmt) == goto_t:
        if stmt.expr.value == self.ea:
          yield stmt.container.block.ea
      elif type(stmt) == branch_t:
        if stmt.true.value == self.ea:
          yield stmt.container.block.ea
        if stmt.false.value == self.ea:
          yield stmt.container.block.ea
    return

  @property
  def jump_from(self):
    """ return a list of blocks where `block` leads to, based on gotos in `block` """
    return [self.function.blocks[ea] for ea in self.jump_from_ea]

class function_t(object):
  def __init__(self, graph):
    self.graph = graph
    self.arch = graph.arch
    self.ea = graph.ea
    self.blocks = {ea: function_block_t(self, node) for ea, node in graph.nodes.iteritems()}
    return

  def __repr__(self):
    return '<%s %x %s>' % (self.__class__.__name__, self.ea, repr(self.blocks.values()))

  @property
  def return_blocks(self):
    for ea, block in self.blocks.iteritems():
      if block.node.is_return_node:
        yield block
    return

  @property
  def entry_block(self):
    return self.blocks[self.ea]


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
class step_registers_pruned(step_t):
  description = 'Dead assignments to registers pruned'
class step_stack_pruned(step_t):
  description = 'Dead assignments to stack pruned'
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

ordered_steps = [
  step_nothing_done,
  step_basic_blocks,
  step_ir_form,
  step_ssa_form_registers,
  step_stack_propagated,
  step_ssa_form_derefs,
  step_calls,
  step_arguments_renamed,
  step_registers_pruned,
  step_stack_pruned,
  step_stack_renamed,
  step_propagated,
  step_locals_renamed,
  step_ssa_removed,
  step_combined,
  step_decompiled,
]

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

    self.calling_convention = 'live_locations'

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

  def solve_call_parameters(self):
    cls = callconv.__conventions__[self.calling_convention]
    resolver = cls(self.function)
    resolver.process()
    return

  def adjust_returns(self):
    for stmt in statement_iterator_t(self.function):
      if isinstance(stmt, return_t):
        if not isinstance(stmt.expr, assignable_t):
          return
        if stmt.expr.definition is not None:
          # early return if one path is initialized
          return
    for stmt in statement_iterator_t(self.function):
      if isinstance(stmt, return_t):
        stmt.expr = None
    return

  def steps(self):
    """ this is a generator function which yeilds the last decompilation step
        which was performed. the caller can then observe the function flow. """

    self.graph = graph.graph_t(self.ea, self.disasm)
    yield self.set_step(step_nothing_done())

    self.graph.find_control_flow()
    yield self.set_step(step_basic_blocks())

    self.graph.transform_ir()
    self.function = function_t(self.graph)
    yield self.set_step(step_ir_form())

    self.ssa_tagger = ssa.ssa_tagger_t(self.function)
    self.ssa_tagger.tag_registers()
    yield self.set_step(step_ssa_form_registers())

    self.propagator = stack_propagator_t(self.function)
    self.propagator.propagate()
    yield self.set_step(step_stack_propagated())

    self.ssa_tagger.tag_derefs()
    self.restored_locations = self.ssa_tagger.restored_locations()
    self.spoiled_locations = self.ssa_tagger.spoiled_locations()
    self.adjust_returns()
    yield self.set_step(step_ssa_form_derefs())

    # properly find function call arguments.
    self.solve_call_parameters()
    yield self.set_step(step_calls())

    self.register_arguments_renamer = register_arguments_renamer_t(self)
    self.register_arguments_renamer.rename()
    self.stack_arguments_renamer = stack_arguments_renamer_t(self)
    self.stack_arguments_renamer.rename()
    self.ssa_tagger.tag_arguments()
    self.ssa_tagger.verify()
    yield self.set_step(step_arguments_renamed())

    # prune unused registers
    self.pruner = pruner.unused_registers_pruner_t(self)
    self.pruner.prune()
    # prune assignments for restored locations
    self.pruner = pruner.restored_locations_pruner_t(self)
    self.pruner.prune()
    # remove unused return registers
    self.pruner = pruner.unused_call_returns_pruner_t(self)
    self.pruner.prune()
    self.ssa_tagger.verify()
    yield self.set_step(step_registers_pruned())

    # remove unused stack assignments
    self.pruner = pruner.unused_stack_locations_pruner_t(self)
    self.pruner.prune()
    yield self.set_step(step_stack_pruned())

    self.stack_variables_renamer = stack_variables_renamer_t(self.function)
    self.stack_variables_renamer.rename()
    self.ssa_tagger.tag_variables()
    yield self.set_step(step_stack_renamed())

    # propagate assignments to local variables.
    self.propagator = registers_propagator_t(self.function)
    self.propagator.propagate()
    self.propagator = call_arguments_propagator_t(self.function)
    self.propagator.propagate()
    self.ssa_tagger.verify()
    yield self.set_step(step_propagated())

    # todo: rename local variables
    yield self.set_step(step_locals_renamed())

    # get us out of ssa form.
    self.ssa_tagger.remove_ssa_form()
    yield self.set_step(step_ssa_removed())

    # after everything is done, we can combine blocks!
    filters.controlflow.run(self.function)
    yield self.set_step(step_combined())

    # done.
    yield self.set_step(step_decompiled())
    return

