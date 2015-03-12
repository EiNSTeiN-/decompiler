
import flow
import ssa

from statements import *
from expressions import *

import filters.simplify_expressions
import callconv

# what are we collecting now
COLLECT_REGISTERS = 1
COLLECT_FLAGS = 2
COLLECT_ARGUMENTS = 4
COLLECT_VARIABLES = 8
COLLECT_DEREFS = 16
COLLECT_ALL = COLLECT_REGISTERS | COLLECT_FLAGS | COLLECT_ARGUMENTS | \
                COLLECT_VARIABLES | COLLECT_DEREFS

PROPAGATE_ANY = 1 # any expression
PROPAGATE_STACK_LOCATIONS = 2 # only stack locations
PROPAGATE_REGISTERS = 4 # only register locations.
PROPAGATE_FLAGS = 8 # only flagloc_t

# if set, propagate only definitions with a single use. otherwise,
# expressions with multiple uses can be propagated (this is
# necessary for propagating stack variables, for example)
PROPAGATE_SINGLE_USES = 512

class simplifier(object):
  """ this class is used to make transformations on the code flow,
  such as replacing uses by their definitions, removing restored
  registers, etc. """

  def __init__(self, flow, flags):

    self.flow = flow
    self.flags = flags

    self.done_blocks = []

    self.return_chains = {}

    return

  def should_collect(self, expr):
    if not isinstance(expr, assignable_t):
      return False

    if self.flags & COLLECT_REGISTERS and type(expr) == regloc_t:
      return True
    if self.flags & COLLECT_FLAGS and type(expr) == flagloc_t:
      return True
    if self.flags & COLLECT_ARGUMENTS and type(expr) == arg_t:
      return True
    if self.flags & COLLECT_VARIABLES and type(expr) == var_t:
      return True
    if self.flags & COLLECT_DEREFS and type(expr) == deref_t:
      return True

    return False

  def find_reg_chain(self, chains, reg):
    """ find the chain that matches this exact register. """

    for chain in chains:
      if chain.defreg == reg:
        return chain

    return

  def get_statement_chains(self, block, stmt, chains):
    """ given a statement, collect all registers that appear
        in it and stuff them in their respective chains. """

    for _stmt in stmt.statements:
      self.get_statement_chains(block, _stmt, chains)

    if type(stmt) == goto_t and type(stmt.expr) == value_t:

      ea = stmt.expr.value
      _block = self.flow.blocks[ea]

      self.get_block_chains(_block, chains)
      return

    regs = [reg for reg in stmt.expr.iteroperands() if self.should_collect(reg)]

    for reg in regs:
      chain = self.find_reg_chain(chains, reg)
      if not chain:
        chain = chain_t(self.flow, reg)
        chains.append(chain)
      instance = instance_t(block, stmt, reg)
      chain.new_instance(instance)

    if type(stmt) == return_t:
      self.return_chains[block] = chains[:]
    return

  def get_block_chains(self, block, chains):
    """ iterate over a block and build chains. """

    if block in self.done_blocks:
      return

    self.done_blocks.append(block)

    for stmt in list(block.container.statements):
      self.get_statement_chains(block, stmt, chains)

    return

  def get_chains(self):
    """ return a list of all chains that should be collected
        according to the 'flags' given. """

    self.done_blocks = []
    chains = []
    self.get_block_chains(self.flow.entry_block, chains)

    return chains

  def can_propagate(self, chain, flags):
    """ return True if this chain can be propagated. """

    defines = chain.defines
    uses = chain.uses

    # prevent removing anything without uses during propagation. we'll do it later.
    if len(uses) == 0 or len(defines) == 0:
      return False

    # no matter what, we cannot propagate if there is more than
    # one definition for this chain with the exception where all
    # the definitions are the same.
    if len(defines) > 1 and not chain.all_same_definitions():
      return False

    definstance = defines[0]
    stmt = definstance.stmt
    if type(stmt.expr) != assign_t:
      # this is not possible in theory.
      return False

    # get the target of the assignement.
    value = stmt.expr.op2

    # never propagate function call if it has more than one use...
    if type(value) == call_t and len(uses) > 1:
      return False

    # prevent multiplying statements if they have more than one use.
    # this should be the subject of a more elaborate algorithm in order
    # to propagate simple expressions whenever possible but limit
    # expression complexity at the same time.

    if type(stmt.expr.op1) == regloc_t:
      return True

    if len(uses) > 1 and (flags & PROPAGATE_SINGLE_USES) != 0:
      return False

    if (flags & PROPAGATE_ANY):
      return True

    if self.flow.arch.is_stackvar(value) and (flags & PROPAGATE_STACK_LOCATIONS):
      return True

    if type(value) == regloc_t and (flags & PROPAGATE_REGISTERS):
      return True

    if type(value) == flagloc_t and (flags & PROPAGATE_FLAGS):
      return True

    return False

  def propagate(self, chains, chain):
    """ take all uses and replace them by the right side of the definition.
    returns True if the propagation was successful. """

    defines = chain.defines

    definstance = defines[0]
    stmt = definstance.stmt

    # get the target of the assignement.
    value = stmt.expr.op2

    ret = False

    for useinstance in list(chain.uses):
      _stmt = useinstance.stmt
      _index = _stmt.index()

      # check if the instance can be propagated. the logic is to avoid
      # propagating past a redefinition of anything that is used in this
      # statement. eg. in the series of statements 'y = x; x = 1; z = y;'
      # the 'y' assignement cannot be propagated because of the assignement
      # to 'x' later.
      right_uses = [reg for reg in value.iteroperands() if self.should_collect(reg)]
      prevent = False
      for reg in right_uses:
        other_chain = self.find_reg_chain(chains, reg)
        if not other_chain:
          continue
        for inst in other_chain.instances:
          if not inst.stmt.container:
            continue
          #~ if inst.reg.is_def:
            #~ print 'is def', str(inst.reg)
          if inst.stmt.index() > _index:
            continue
          if inst.reg.is_def and inst.stmt.index() > stmt.index():
            prevent = True
            break

      if prevent:
        print 'prevent...', str(stmt), 'into', str(_stmt)
        continue

      useinstance.reg.replace(value.copy())

      chain.instances.remove(useinstance)
      filters.simplify_expressions.run(_stmt.expr, deep=True)

      # handle special case where statement is simplified into itself
      if type(_stmt.expr) == assign_t and _stmt.expr.op1 == _stmt.expr.op2:
        _stmt.remove()

      ret = True

    # if definition was propagated fully, then remove its definition statement
    if len(chain.uses) == 0:
      for define in defines:
        define.stmt.remove()
      chains.remove(chain)

    return ret

  def propagate_all(self, flags):
    """ collect all chains in this function flow, then propagate
        them if possible. """

    while True:
      redo = False

      chains = self.get_chains()

      for chain in chains:
        if not self.can_propagate(chain, flags):
          continue
        redo = self.propagate(chains, chain) or redo

      if not redo:
        break

      return

  def remove_unused_definitions(self):
    """ Remove definitions that don't have any uses.
        Do it recursively, because as we remove some, others may becomes
        unused.
    """

    while True:
      redo = False

      chains = self.get_chains()
      for chain in chains:
        if len(chain.uses) > 0:
          continue

        for instance in chain.defines:
          stmt = instance.stmt
          if type(stmt.expr) == call_t:
            # do not eliminate calls
            continue
          elif type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
            # simplify 'reg = call()' form if reg is a register and is no longer used.
            if type(stmt.expr.op1) == regloc_t:
              stmt.expr = stmt.expr.op2
            continue

          # otherwise remove the statement
          stmt.remove()
          redo = True

      if not redo:
          break

    return

class iterator_t(object):
  def __init__(self, flow):
    self.flow = flow
    return

class block_iterator_t(iterator_t):
  def __iter__(self):
    for block in self.flow.iterblocks():
      yield block

class container_iterator_t(iterator_t):
  def __iter__(self):
    for block in block_iterator_t(self.flow):
      yield block.container

class statement_iterator_t(iterator_t):
  def __iter__(self):
    for container in container_iterator_t(self.flow):
      for stmt in container.statements:
        yield stmt

class expression_iterator_t(iterator_t):
  def __iter__(self):
    for stmt in statement_iterator_t(self.flow):
      for expr in stmt.expressions:
        yield expr

class operand_iterator_t(iterator_t):
  def __init__(self, flow, depth_first=False, ltr=True):
    self.depth_first = depth_first
    self.ltr = ltr
    iterator_t.__init__(self, flow)
    return

  def __iter__(self):
    for expr in expression_iterator_t(self.flow):
      for op in expr.iteroperands(self.depth_first, self.ltr):
        yield op

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

STEP_NONE = 0                   # flow_t is empty
STEP_BASIC_BLOCKS_FOUND = 1     # flow_t contains only basic block information
STEP_IR_DONE = 2                # flow_t contains the intermediate representation
STEP_SSA_DONE = 3               # flow_t contains the ssa form
STEP_CALLS_DONE = 4             # call information has been applied to function flow
STEP_RENAMED = 5          # stack locations and registers have been renamed
STEP_PROPAGATED = 6             # assignments have been fully propagated
STEP_PRUNED = 7                 # dead code has been pruned
STEP_COMBINED = 8               # basic blocks have been combined together

STEP_DECOMPILED=STEP_COMBINED   # last step

class decompiler_t(object):

  phase_name = [
    'Nothing done yet',
    'Basic block information found',
    'Intermediate representation form',
    'Static Single Assignment form',
    'Call information found',
    'Locations renamed',
    'Expressions propagated',
    'Dead code pruned',
    'Decompiled',
  ]

  def __init__(self, disasm, ea):
    self.ea = ea
    self.disasm = disasm
    self.current_step = None

    # ssa_tagger_t object
    self.ssa_tagger = None

    self.stack_indices = {}
    self.var_n = 0

    return

  def set_step(self, step):
    self.current_step = step
    return self.current_step

  def step_until(self, stop_step):
    """ decompile until the given step. """
    for step in self.steps():
      if step >= stop_step:
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

  def is_stack_location(self, op):
    for alt in ssa.alternate_form_iterator_t(op, include_self=True):
      if self.disasm.is_stackvar(alt):
        return alt
    return

  def rename_stack_locations(self):
    renamed = True
    while renamed:
      renamed = False
      for op in operand_iterator_t(self.flow, depth_first=False):
        print 'operand', repr(op)
        expr = self.is_stack_location(op)
        print '  renaming', repr(expr)
        if not expr:
          continue

        if type(expr) == regloc_t and self.disasm.is_stackreg(expr):
          # just 'esp'
          index = 0
        elif type(expr) == sub_t:
          # something like 'esp - 4'
          index = -(expr.op2.value)
        elif type(expr) == add_t:
          # something like 'esp + 4'
          index = expr.op2.value

        var = var_t(op.copy())
        if index in self.stack_indices:
          var.name = 's%u' % (self.stack_indices[index], )
        else:
          var.name = 's%u' % (self.var_n, )
          self.stack_indices[index] = self.var_n
          self.var_n += 1

          print 'index', repr(index), repr(op), repr(var)

        op.replace(var)
        renamed = True
        break

    return

  def steps(self):
    """ this is a generator function which yeilds the last decompilation step
        which was performed. the caller can then observe the function flow. """

    self.flow = flow.flow_t(self.ea, self.disasm)
    yield self.set_step(STEP_NONE)

    self.flow.find_control_flow()
    yield self.set_step(STEP_BASIC_BLOCKS_FOUND)

    self.flow.transform_ir()
    yield self.set_step(STEP_IR_DONE)

    # tag all registers so that each instance of a register can be uniquely identified.
    self.ssa_tagger = ssa.ssa_tagger_t(self.flow)
    self.ssa_tagger.tag()
    yield self.set_step(STEP_SSA_DONE)

    conv = callconv.systemv_x64_abi()
    #self.solve_call_parameters(t, conv)
    yield self.set_step(STEP_CALLS_DONE)


    self.rename_stack_locations()
    #self.rename_register_locations()
    yield self.set_step(STEP_RENAMED)



    #~ # This propagates special flags.
    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ # re-propagate after gluing pre/post increments
    #~ #s = simplifier(self.flow, COLLECT_ALL)
    #~ #s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_ANY | PROPAGATE_SINGLE_USES)

    yield self.set_step(STEP_PROPAGATED)



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

    yield self.set_step(STEP_PRUNED)



    #~ # after everything is done, we can combine blocks!
    #~ self.flow.combine_blocks()
    yield self.set_step(STEP_COMBINED)

    return

