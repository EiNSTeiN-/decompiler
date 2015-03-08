
import flow
import ssa

from statements import *
from expressions import *

import filters.simplify_expressions
import callconv
from du import du_t

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

  def process_restores(self):
    """ we try to find chains for any 'x' that has a single
    definition of the style 'x = y' and where all uses are
    of the style 'y = x' and y is either a stack location
    or the same register (not taking the index into account).

    one further condition is that all definitions of 'y' have
    no uses and be live at the return statement.
    """

    #~ print 'at restore'
    chains = self.get_chains()

    restored_regs = []
    #~ print repr(chains)

    for chain in chains:
      defs = chain.defines
      uses = chain.uses

      if len(defs) != 1 or len(uses) == 0:
          continue

      defstmt = defs[0].stmt
      if type(defstmt.expr) != assign_t:
          continue

      def_chain = self.find_reg_chain(chains, defstmt.expr.op2)
      if not def_chain or len(def_chain.uses) != 1:
          continue

      defreg = def_chain.defreg

      all_restored = True

      for use in uses:

        if type(use.stmt.expr) != assign_t:
          all_restored = False
          break

        usechain = self.find_reg_chain(chains, use.stmt.expr.op1)
        if not usechain or len(usechain.defines) != 1:
          all_restored = False
          break

        reg = usechain.defines[0].reg
        if type(defreg) != type(reg):
          all_restored = False
          break

        if type(reg) == regloc_t and (reg.which != defreg.which):
          all_restored = False
          break

        if type(reg) != regloc_t and (reg != defreg):
          all_restored = False
          break

      if all_restored:
        #~ print 'restored', str(defreg)

        # pop all statements in which the restored location appears
        for inst in chain.instances:
          inst.stmt.remove()

        reg = defreg.copy()
        reg.index = None
        restored_regs.append(reg)

    print 'restored regs', repr([str(r) for r in restored_regs])

    return restored_regs

  class arg_collector(object):

    def __init__(self, flow, conv, chains):
      self.flow = flow
      self.conv = conv
      self.chains = chains
      return

    def iter(self, block, container, stmt):

      if type(stmt.expr) == call_t:
        call = stmt.expr
      elif type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
        call = stmt.expr.op2
      else:
          return

      live = []

      for chain in self.chains:
        for instance in chain.instances:
          inst_index = instance.stmt.index()
          if instance.stmt.container != container:
            continue
          if inst_index >= stmt.index():
            continue
          if instance.reg.is_def:
            live.append(instance.stmt)

      self.conv.process_stack(self.flow, block, stmt, call, live)

      return

  def collect_argument_calls(self, conv):
    chains = self.get_chains()
    c = self.arg_collector(self.flow, conv, chains)
    iter = flow_iterator(self.flow, statement_iterator=c.iter)
    iter.do()
    return

  def glue_increments_collect(self, block, container):
    """ for a statement, get all registers that appear in it. """

    chains = []

    for stmt in container.statements:
      regs = [reg for reg in stmt.expr.iteroperands() if self.should_collect(reg)]

      for reg in regs:
        chain = self.find_reg_chain(chains, reg)
        if not chain:
          chain = chain_t(self.flow, reg)
          chains.append(chain)
        instance = instance_t(block, stmt, reg)
        chain.new_instance(instance)

    #~ print 'current', str(block)

    while True:
      redo = False

      # now for each chain, check if they contain increments
      for chain in chains:
        continuous = []

        i = 0
        while i < len(chain.instances):
          all = []
          j = i
          while True:
            if j >= len(chain.instances):
              break

            next = chain.instances[j]
            #~ next_index = next.stmt.index()
            #~ print 'b', str(next.stmt)

            if len([a for a in all if a.stmt == next.stmt]) > 0:
              j += 1
              continue

            #~ if last_index + 1 != next_index:
                #~ break

            if not self.is_increment(chain.defreg, next.stmt.expr) or \
                  not next.reg.is_def:
              break

            #~ last_index = next_index
            all.append(next)
            j += 1

          if len(all) == 0:
            i += 1
            continue

          #~ j += 1
          if j < len(chain.instances):
            next = chain.instances[j]
            #~ next_index = next.stmt.index()
            #~ if last_index + 1 == next_index:
            all.append(next)

          if i > 0:
            this = chain.instances[i-1]
            if not this.reg.is_def:
              #~ i = chain.instances.index(this)
              expr = this.stmt.expr
              #~ last_index = this.stmt.index()
              #~ print 'a', str(expr)

              all.insert(0, this)
          continuous.append(all)
          i = j

        #~ for array in continuous:
          #~ print 'continuous statements:'
          #~ for instance in array:
            #~ print '->', str(instance.stmt)

        # at this point we are guaranteed to have a list with possibly
        # a statement at the beginning, one or more increments in the
        # middle, and possibly another statement at the end.

        for array in continuous:
          pre = array.pop(0) if not self.is_increment(chain.defreg, array[0].stmt.expr) else None
          post = array.pop(-1) if not self.is_increment(chain.defreg, array[-1].stmt.expr) else None

          if pre:
            instances = self.get_nonincrements_instances(pre.stmt.expr, chain.defreg)

            #~ print 'a', repr([str(reg) for reg in instances])
            while len(instances) > 0 and len(array) > 0:
              increment = array.pop(0)
              cls = postinc_t if type(increment.stmt.expr.op2) == add_t else postdec_t
              instance = instances.pop(-1)
              #~ pre.stmt.expr = self.merge_increments(pre.stmt.expr, instance, cls)
              instance.replace(cls(instance.copy()))
              increment.stmt.remove()
              chain.instances.remove(increment)

          if post:
            instances = self.get_nonincrements_instances(post.stmt.expr, chain.defreg)

            #~ print 'b', repr([str(reg) for reg in instances])
            while len(instances) > 0 and len(array) > 0:
              increment = array.pop(0)
              cls = preinc_t if type(increment.stmt.expr.op2) == add_t else predec_t
              instance = instances.pop(-1)
              #~ post.stmt.expr = self.merge_increments(post.stmt.expr, instance, cls)
              instance.replace(cls(instance.copy()))
              increment.stmt.remove()
              chain.instances.remove(increment)

      if not redo:
          break

    return

  def get_nonincrements_instances(self, expr, defreg):
    """ get instances of 'reg' that are not already surrounded by an increment or decrement """

    instances = [reg for reg in expr.iteroperands() if reg == defreg]
    increments = [reg for reg in expr.iteroperands() if type(reg) in (preinc_t, postinc_t, predec_t, postdec_t)]

    real_instances = []
    for instance in instances:
      found = False
      for increment in increments:
        if increment.op is instance:
          found = True
          break
      if not found:
        real_instances.append(instance)

    return real_instances

  def is_increment(self, what, expr):
    return (type(expr) == assign_t and type(expr.op2) in (add_t, sub_t) and \
                type(expr.op2.op2) == value_t and expr.op2.op2.value == 1 and \
                expr.op1 == expr.op2.op1 and expr.op1 == what)

  def glue_increments(self):
    iter = flow_iterator(self.flow, container_iterator=self.glue_increments_collect)
    iter.do()
    return

class flow_iterator(object):
  """ Helper class for iterating a flow_t object.

  The following callbacks can be used:
      block_iterator(block_t)
      container_iterator(block_t, container_t)
      statement_iterator(block_t, container_t, statement_t)
      expression_iterator(block_t, container_t, statement_t, expr_t)

  any callback can return False to stop the iteration.
  """

  def __init__(self, flow, **kwargs):
    self.flow = flow

    self.block_iterator = kwargs.get('block_iterator')
    self.container_iterator = kwargs.get('container_iterator')
    self.statement_iterator = kwargs.get('statement_iterator')
    self.expression_iterator = kwargs.get('expression_iterator')

    return

  def do_expression(self, block, container, stmt, expr):

    r = self.expression_iterator(block, container, stmt, expr)
    if r is False:
      # stop iterating.
      return False

    if isinstance(expr, expr_t):
      for i in range(len(expr)):
        r = self.do_expression(block, container, stmt, expr[i])
        if r is False:
          # stop iterating.
          return False

    return

  def do_statement(self, block, container, stmt):

    if self.statement_iterator:
      r = self.statement_iterator(block, container, stmt)
      if r is False:
        # stop iterating.
        return

    if self.expression_iterator and stmt.expr is not None:
      r = self.do_expression(block, container, stmt, stmt.expr)
      if r is False:
        # stop iterating.
        return False

    if type(stmt) == goto_t and type(stmt.expr) == value_t:
      block = self.flow.get_block(stmt)
      self.do_block(block)
      return

    for _container in stmt.containers:
      r = self.do_container(block, _container)
      if r is False:
        # stop iterating.
        return False

    return

  def do_container(self, block, container):

    if self.container_iterator:
      r = self.container_iterator(block, container)
      if r is False:
        return

    for stmt in container.statements:
      r = self.do_statement(block, container, stmt)
      if r is False:
        # stop iterating.
        return False

    return

  def do_block(self, block):

    if block in self.done_blocks:
      return

    self.done_blocks.append(block)

    if self.block_iterator:
      r = self.block_iterator(block)
      if r is False:
        # stop iterating.
        return False

    r = self.do_container(block, block.container)
    if r is False:
      # stop iterating.
      return False

    return

  def do(self):
    self.done_blocks = []
    block = self.flow.entry_block
    self.do_block(block)
    return

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
STEP_PROPAGATED = 5             # assignments have been fully propagated
STEP_PRUNED = 6                 # dead code has been pruned
STEP_COMBINED = 7               # basic blocks have been combined together

STEP_DECOMPILED=STEP_COMBINED   # last step

class decompiler_t(object):

  phase_name = [
    'Nothing done yet',
    'Basic block information found',
    'Intermediate representation form',
    'Static Single Assignment form',
    'Call information found',
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

    return

  def step_until(self, stop_step):
    """ decompile until the given step. """

    for step in self.step():
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

  def get_arguments(self, ssa_tagger):
    args = []
    i = 0
    for expr in ssa_tagger.uninitialized_regs:
      arg = arg_t(expr, 'arg%u' % i)
      arg.index = expr.index
      i += 1
      args.append(arg)
    return args

  def has_side_effects(self, stmt):
    """ return True if a statement has 'side effects' that would prevent its elimination.

        In this category we include any function calls, any assignment to global locations,
        and possibly some more. """

    for expr in stmt.expressions:
      for op in expr:
        if type(op) == call_t:
          return True
        if type(op) == deref_t and op.is_def:
          return True
    return

  def propagate(self, du):

    while True:
      removed_something = False

      for index, chain in du.map.items():
        if chain.loc is None:
          continue

        stmt = chain.loc.parent_statement
        if not stmt:
          print 'cannot find parent statement of expr %s' % (repr(chain.loc), )
          continue

        if self.has_side_effects(stmt):
          continue

        if len(chain.uses) == 0:
          du.remove(stmt)
          stmt.remove()

          # mark for another pass.
          removed_something = True

      # break out of loop if we did remove any statement during this pass.
      if not removed_something:
        break

      return

  def get_return_locations(self):
    """ get all statements that return from the function
        (returns, or no-return calls, or tail recursion jumps...). """

    #~ returns = []
    #~ for ea, block in self.flow.blocks.items():
      #~ if len(block.container) == 0:
        #~ continue
      #~ stmt = block.container[-1]
      #~ if type(stmt) == return_t:
        #~ returns.append(block)
    return returns

    def get_restored_regs(self, ssa_tagger, du):
      #~ returns = get_return_locations()
      #~ regmap = {}
      #~ for block in returns:
        #~ for stmt in reversed(block.container):
          #~ if type(stmt) == statement_t and type(stmt.expr) == assign_t and \
                #~ type(stmt.expr.op1) == regloc_t:
            #~ if stmt.expr.op1.which not in regmap:
              #~ regmap
      return

  def steps(self):
    """ this is a generator function which yeilds the last decompilation step
        which was performed. the caller can then observe the function flow. """

    self.flow = flow.flow_t(self.ea, self.disasm)
    self.current_step = STEP_NONE
    yield self.current_step

    self.flow.find_control_flow()
    self.current_step = STEP_BASIC_BLOCKS_FOUND
    yield self.current_step

    self.flow.transform_ir()
    self.current_step = STEP_IR_DONE
    yield self.current_step

    # tag all registers so that each instance of a register can be uniquely identified.
    self.ssa_tagger = ssa.ssa_tagger_t(self.flow)
    self.ssa_tagger.tag()

    #~ du = du_t(self.flow, t.uninitialized_regs)
    #~ du.populate()

    self.current_step = STEP_SSA_DONE
    yield self.current_step

    conv = callconv.systemv_x64_abi()
    self.solve_call_parameters(t, conv)
    self.current_step = STEP_CALLS_DONE
    yield self.current_step

    # TODO: before we remove anything: find restored registers.
    # TODO: transform any dereference into a var_t if possible (i.e. stack locations, or globals)

    #~ yield STEP_PROPAGATED

    #~ args = self.get_arguments(t)
    #~ du = du_t(self.flow, args)
    #~ du.populate()
    #~ self.propagate(du)
    #~ yield STEP_PRUNED

    #~ # After registers are tagged, we can replace their uses by their definitions. this
    #~ # takes care of eliminating any instances of 'esp' which clears the way for
    #~ # determining stack variables correctly.
    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_STACK_LOCATIONS)

    #~ # remove special flags (eflags) definitions that are not used, just for clarity
    #~ s = simplifier(self.flow, COLLECT_FLAGS)
    #~ s.remove_unused_definitions()

    #~ s = simplifier(self.flow, COLLECT_REGISTERS)
    #~ s.remove_unused_definitions()

    #~ # rename stack variables to differentiate them from other dereferences.
    #~ r = renamer(self.flow, RENAME_STACK_LOCATIONS)
    #~ r.wrap_variables()

    #~ # collect function arguments that are passed on the stack
    #~ #s = simplifier(self.flow, COLLECT_ALL)
    #~ #s.collect_argument_calls(conv)

    #~ # This propagates special flags.
    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ # At this point we must take care of removing increments and decrements
    #~ # that are in their own statements and "glue" them to an adjacent use of
    #~ # that location.
    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.glue_increments()

    #~ # re-propagate after gluing pre/post increments
    #~ #s = simplifier(self.flow, COLLECT_ALL)
    #~ #s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    #~ s = simplifier(self.flow, COLLECT_ALL)
    #~ s.propagate_all(PROPAGATE_ANY | PROPAGATE_SINGLE_USES)

    #~ # eliminate restored registers. during this pass, the simplifier also collects
    #~ # stack variables because registers may be preserved on the stack.
    #~ s = simplifier(self.flow, COLLECT_REGISTERS | COLLECT_VARIABLES)
    #~ s.process_restores()
    #~ # ONLY after processing restores can we do this; any variable which is assigned
    #~ # and never used again is removed as dead code.
    #~ s = simplifier(self.flow, COLLECT_REGISTERS)
    #~ s.remove_unused_definitions()

    #~ # rename registers to pretty names.
    #~ r = renamer(self.flow, RENAME_REGISTERS)
    #~ r.fct_arguments = [] #t.fct_arguments
    #~ r.wrap_variables()


    #~ # after everything is done, we can combine blocks!
    #~ self.flow.combine_blocks()
    #~ yield STEP_COMBINED

    return

