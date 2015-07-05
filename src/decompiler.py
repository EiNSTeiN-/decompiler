
import graph
import ssa
import propagator
from iterators import *
import pruner
import renamer

from statements import *
from expressions import *

import filters.controlflow
import callconv

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

    self.uninitialized_stmt = statement_t(0, params_t())
    self.uninitialized = self.uninitialized_stmt.expr
    return

  @property
  def arguments(self):
    for expr in self.uninitialized:
      if isinstance(expr, arg_t) and len(expr.uses) > 0:
        yield expr
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
  def __init__(self, decompiler):
    self.decompiler = decompiler
    self.ea = decompiler.ea
    self.disasm = decompiler.disasm
    self.function = decompiler.function
    self.ssa_tagger = decompiler.ssa_tagger
    self.calling_convention = decompiler.calling_convention
    return

  def run(self):
    pass

class step_nothing_done(step_t):
  'Nothing done yet'
  def run(self):
    return

class step_basic_blocks(step_t):
  'Basic block information ready'
  def run(self):
    self.decompiler.graph = graph.graph_t(self.ea, self.disasm)
    self.decompiler.graph.find_control_flow()
    return

class step_ir_form(step_t):
  'Intermediate form is ready'
  def run(self):
    self.decompiler.graph.transform_ir()
    self.decompiler.function = function_t(self.decompiler.graph)
    self.decompiler.ssa_tagger = ssa.ssa_tagger_t(self.decompiler.function)
    return

class step_ssa_form_registers(step_t):
  'Static single assignment form (registers)'
  def run(self):
    self.ssa_tagger.tag_registers()
    return

class step_stack_propagated(step_t):
  'Stack variable is propagated'
  def run(self):
    p = propagator.stack_propagator_t(self.function)
    p.propagate()
    self.ssa_tagger.verify()
    return

class step_ssa_form_derefs(step_t):
  'Static single assignment form (dereferences)'
  def run(self):
    self.ssa_tagger.tag_derefs()
    self.decompiler.restored_locations = self.ssa_tagger.restored_locations()
    self.decompiler.spoiled_locations = self.ssa_tagger.spoiled_locations()
    self.adjust_returns()
    return

  def adjust_returns(self):
    for stmt in statement_iterator_t(self.function):
      if isinstance(stmt, return_t):
        if not isinstance(stmt.expr, assignable_t):
          return
        if stmt.expr.definition not in self.function.uninitialized:
          # early return if one path is initialized
          return
        if len(stmt.expr.definition.uses) != 1:
          # early return if one path is initialized
          return
    for stmt in statement_iterator_t(self.function):
      if isinstance(stmt, return_t):
        stmt.expr = None
    return

class step_calls(step_t):
  'Call information found'
  def run(self):
    # properly find function call arguments.
    self.solve_call_parameters()
    return

  def solve_call_parameters(self):
    cls = callconv.__conventions__[self.calling_convention]
    resolver = cls(self.function)
    resolver.process()

    # unlink all stack addresses, so we can eliminate assignments
    # to esp that are dead.
    for call in operand_iterator_t(self.function, klass=call_t):
      call.stack.unlink()
      call.stack = None
    return

class step_arguments_renamed(step_t):
  'Arguments are renamed'
  def run(self):
    r = renamer.register_arguments_renamer_t(self.decompiler)
    r.rename()

    r = renamer.stack_arguments_renamer_t(self.decompiler)
    r.rename()

    self.ssa_tagger.tag_arguments()
    self.ssa_tagger.verify()
    return

class step_registers_pruned(step_t):
  'Dead assignments to registers pruned'
  def run(self):
    # prune unused registers
    p = pruner.unused_registers_pruner_t(self.decompiler)
    p.prune()

    # prune assignments for restored locations
    p = pruner.restored_locations_pruner_t(self.decompiler)
    p.prune()

    # remove unused return registers
    p= pruner.unused_call_returns_pruner_t(self.decompiler)
    p.prune()

    self.ssa_tagger.verify()
    return

class step_stack_renamed(step_t):
  'Stack locations and registers are renamed'
  def run(self):
    r = renamer.stack_variables_renamer_t(self.function)
    r.rename()

    self.ssa_tagger.tag_variables()
    self.ssa_tagger.verify()
    return

class step_stack_pruned(step_t):
  'Dead assignments to stack pruned'
  def run(self):
    # remove unused stack assignments
    p = pruner.unused_stack_locations_pruner_t(self)
    p.prune()

    self.ssa_tagger.verify()
    return

class step_propagated(step_t):
  'Assignments have been propagated'
  def run(self):
    # propagate assignments to local variables.
    p = propagator.registers_propagator_t(self.function)
    p.propagate()

    p = propagator.call_arguments_propagator_t(self.function)
    p.propagate()

    self.ssa_tagger.verify()
    return

class step_locals_renamed(step_t):
  'Local variable locations and registers are renamed'
  def run(self):
    # todo: rename local variables
    return

class step_ssa_removed(step_t):
  'Function is transformed out of ssa form'
  def run(self):
    # get us out of ssa form.
    self.ssa_tagger.remove_ssa_form()
    return

class step_combined(step_t):
  'Basic blocks are reassembled'
  def run(self):
    # after everything is done, we can combine blocks!
    filters.controlflow.run(self.function)
    return

class step_decompiled(step_t):
  'Stack locations and registers are renamed'

class decompiler_t(object):
  """ Decompiler. """

  # ordered steps
  STEPS = [
    step_nothing_done,
    step_basic_blocks,
    step_ir_form,
    step_ssa_form_registers,
    step_stack_propagated,
    step_ssa_form_derefs,
    step_calls,
    step_arguments_renamed,
    step_registers_pruned,
    step_stack_renamed,
    step_stack_pruned,
    step_propagated,
    step_locals_renamed,
    step_ssa_removed,
    step_combined,
    step_decompiled,
  ]

  def __init__(self, disasm, ea):
    self.ea = ea
    self.disasm = disasm
    self.calling_convention = 'live_locations'

    self.step_generator = self.steps()
    self.current_step = None
    self.previous_steps = []

    self.graph = None
    self.function = None
    self.ssa_tagger = None
    return

  def run_step(self, klass):
    step = klass(self)
    step.run()
    self.current_step = step
    self.previous_steps.append(step)
    return self.current_step

  def step_until(self, stop_step):
    """ decompile until the given step. """
    for step in self.step_generator:
      if step.__class__ == stop_step:
        break
    return

  def steps(self):
    """ this is a generator function which yields each decompilation steps
        as they are performed, which allows the caller can then observe the
        intermediate result of each step. """
    for klass in self.STEPS:
      yield self.run_step(klass)
    return

