""" Transform a function into and out of SSA form.

"""

import propagator
import iterators

from statements import *
from expressions import *

import filters.simplify_expressions

class defined_loc_t(object):

  def __init__(self, block, loc):
    self.block = block
    self.loc = loc
    return

  def __eq__(self, other):
    return isinstance(other, self.__class__) and other.loc == self.loc

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.block, self.loc))

  def is_definition_of(self, other):
    return other.no_index_eq(self.loc)

class ssa_context_t(object):
  """ the context holds live locations at any given point in time.
      it is used by the tagger to find live uses during tagging. """

  def __init__(self):
    self.defined = []
    return

  def copy(self):
    ctx = ssa_context_t()
    ctx.defined = self.defined[:]
    return ctx

  def get_definition(self, expr):
    obj = self.get_definition_object(expr)
    if obj:
      return obj.loc

  def get_definition_object(self, expr):
    for _loc in self.defined:
      if _loc.is_definition_of(expr):
        return _loc

  def add_uninitialized_loc(self, block, expr):
    loc = defined_loc_t(block, expr)
    self.defined.append(loc)
    return

  def assign(self, block, expr):
    loc = defined_loc_t(block, expr)
    obj = self.get_definition_object(expr)
    if obj:
      self.defined.remove(obj)
    self.defined.append(loc)
    return

SSA_STEP_NONE = 0
SSA_STEP_REGISTERS = 1
SSA_STEP_DEREFERENCES = 2
SSA_STEP_ARGUMENTS = 3
SSA_STEP_VARIABLES = 4

class ssa_tagger_t(object):
  """ The SSA tagger iterates through the blocks in the control flow,
      and inserts phi-functions at appropriate locations. After doing so,
      it becomes trivial to determine which locations in the flow are
      uninitialized, restored, etc. """

  def __init__(self, function):
    self.function = function

    self.tagger_step = SSA_STEP_NONE

    self.index = 0

    # keep track of any block which we have already walked into, because at
    # this stage we may still encounter recursion (gotos that lead backwards).
    self.done_blocks = []

    # list of `assignable_t` that are _never_ defined anywhere within
    # the scope of this function.
    self.uninitialized = []

    # dict of `node_t` : [`expr_t`, ...]
    # contains contexts at the exit of each block.
    self.exit_contexts = {}

    # dict of `node_t` : [`expr_t`, ...]
    # contains each block and a list of thier phi assignments.
    self.block_phis = {}

    return

  def is_correct_step(self, loc):

    if not isinstance(loc, assignable_t):
      return False

    if isinstance(loc, regloc_t) and self.tagger_step == SSA_STEP_REGISTERS:
      return True

    if isinstance(loc, deref_t) and self.tagger_step == SSA_STEP_DEREFERENCES:
      return True

    if isinstance(loc, var_t) and self.tagger_step == SSA_STEP_VARIABLES:
      return True

    if isinstance(loc, arg_t) and self.tagger_step == SSA_STEP_ARGUMENTS:
      return True

    return False

  def get_defs(self, expr):
    return [defreg for defreg in expr.iteroperands() if self.is_correct_step(defreg) and defreg.is_def]

  def get_uses(self, expr):
    return [defreg for defreg in expr.iteroperands() if self.is_correct_step(defreg) and not defreg.is_def]

  def same_loc(self, a, b):
    return a.clean() == b.clean()

  def tag_uninitialized(self, expr):
    found = False
    for loc in self.uninitialized:
      if self.same_loc(loc, expr):
        expr.index = loc.index
        return

    expr.index = self.index
    self.index += 1
    self.uninitialized.append(expr)
    return

  def insert_phi(self, block, lastdef, thisdef):
    newuse = lastdef.copy(with_definition=True)
    parent = thisdef.parent_statement

    stmt = statement_t(parent.ea, assign_t(thisdef.copy(), phi_t(newuse)))
    block.container.insert(parent.index(), stmt)

    if lastdef.is_def:
      newuse.definition = lastdef

    self.block_phis[block].append(stmt)
    return stmt

  def need_phi(self, context, block, expr):
    obj = context.get_definition_object(expr)
    return obj and (obj.block is not block or (obj.loc.parent_statement.index() > expr.parent_statement.index()))

  def tag_use(self, context, block, expr):
    if self.need_phi(context, block, expr):
      # expr is defined in another block.

      lastdef = context.get_definition(expr)
      if lastdef:
        stmt = self.insert_phi(block, lastdef, expr)

        context.assign(block, stmt.expr.op1)
        stmt.expr.op1.index = self.index
        self.index += 1

        expr.index = stmt.expr.op1.index
        expr.definition = stmt.expr.op1
        return

    lastdef = context.get_definition(expr)
    if lastdef:
      # the location is previously defined.
      expr.index = lastdef.index
      expr.definition = lastdef
    else:
      # the location is not defined, it's external to the function.
      self.tag_uninitialized(expr)
      context.add_uninitialized_loc(block, expr)

    return

  def clean_du(self, loc):
    loc.definition = None
    for use in loc.uses:
      use.definition = None
    return loc

  def tag_phis(self, context, block):
    """ insert new locations from the current context in all
        phi-functions present in the target block. """
    for stmt in self.block_phis[block]:
      loc = stmt.expr.op1
      lastdef = context.get_definition(loc)
      if lastdef and lastdef != loc:
        if lastdef in stmt.expr.op2.operands:
          continue
        newuse = self.clean_du(lastdef.copy(with_definition=True))
        stmt.expr.op2.append(newuse)
        newuse.definition = lastdef
    return

  def tag_uses(self, context, block, expr):
    for use in self.get_uses(expr):
      self.tag_use(context, block, use)
    return

  def tag_defs(self, context, block, expr):
    for _def in self.get_defs(expr):
      context.assign(block, _def)
      if _def.index is None:
        _def.index = self.index
        self.index += 1
    return

  def statement(self, context, stmt):
    """ implement this method in a subclass """
    return

  def tag_uninitialized_uses(self, context, block):
    for stmt in list(block.container.statements):
      for expr in stmt.expressions:
        for use in self.get_uses(expr):
          if isinstance(use, assignable_t) and use.definition is None and type(use.parent) is not phi_t:
            if self.need_phi(context, block, use):
              lastdef = context.get_definition(use)
              stmt = self.insert_phi(block, lastdef, use)
              stmt.expr.op1.index = use.index
              use.definition = stmt.expr.op1
              for _use in use.uses:
                _use.definition = None
                _use.definition = stmt.expr.op1
    return

  def tag_block(self, context, block):

    if block in self.done_blocks:
      self.tag_phis(context, block)
      self.tag_uninitialized_uses(context, block)
      return

    self.done_blocks.append(block)
    self.block_phis[block] = []

    for stmt in list(block.container.statements):
      for expr in stmt.expressions:
        self.tag_uses(context, block, expr)
        self.tag_defs(context, block, expr)

      self.statement(context, stmt)

      if type(stmt) == goto_t and stmt.is_known() and \
            stmt.expr.value in self.function.blocks:
        target = self.function.blocks[stmt.expr.value]
        self.tag_block(context.copy(), target)
      elif type(stmt) == branch_t:
        for expr in (stmt.true, stmt.false):
          target = self.function.blocks[expr.value]
          if target:
            self.tag_block(context.copy(), target)
      elif type(stmt) == return_t:
        break

    if self.tagger_step != SSA_STEP_NONE:
      self.exit_contexts[self.tagger_step][block] = context.copy()

    return

  def tag_step(self, step):
    self.done_blocks = []
    self.tagger_step = step
    self.exit_contexts[self.tagger_step] = {}
    context = ssa_context_t()
    self.tag_block(context, self.function.entry_block)
    self.simplify()
    return

  def tag_registers(self):
    return self.tag_step(SSA_STEP_REGISTERS)

  def tag_derefs(self):
    return self.tag_step(SSA_STEP_DEREFERENCES)

  def tag_arguments(self):
    return self.tag_step(SSA_STEP_ARGUMENTS)

  def tag_variables(self):
    return self.tag_step(SSA_STEP_VARIABLES)

  def is_restored(self, expr):
    if expr in self.uninitialized:
      return expr
    start = [expr]
    checked = [] # keep track of checked values to avoid recursion
    while len(start) > 0:
      current = start.pop(0)
      checked.append(current)
      rvalue = current.parent_statement.expr.op2
      if isinstance(rvalue, phi_t):
        for t in rvalue:
          if t.definition:
            if t.definition not in checked:
              start.append(t.definition)
          elif t in self.uninitialized and expr.no_index_eq(t):
            return t
      elif not isinstance(rvalue, assignable_t):
        continue
      elif rvalue.definition:
        if rvalue.definition not in checked:
          start.append(rvalue.definition)
      elif rvalue in self.uninitialized and expr.no_index_eq(rvalue):
        return rvalue
    return

  def restored_locations(self):
    """ Find all restored locations.

      A restored location is defined as any location (register
      or dereference) which resolves to the original value it had
      at the entry point of the function. By definition, all
      restored locations also appear in `self.uninitialized`.

      Returns an dict of {`exit`: `original`} where `exit` is the
      restored expression at the return location (for example, `ebp@4`)
      and `original` is the restored expression at the entry point of
      the function (for example, `ebp@0`). `exit` and `original` may
      be the same expression, which mean the expression is used without
      being initialized but is still the same at the return location.

      When there are multiple return locations in the function, all
      of them have to agree that a location is restored, otherwise
      the location is not returned here. If all return locations agree,
      the same register will appear several times in the returned dict.
      For example: `{ebp@3: ebp@0, ebp@7: ebp@0}` means both `ebp@2`
      and `ebp@7` are restored to the original value `ebp@0` at all
      return locations.
    """

    restored_grouped = {}
    return_blocks = list(self.function.return_blocks)

    for rblock in return_blocks:
      for contexts in self.exit_contexts.values():
        if not rblock in contexts:
          continue
        rcontext = contexts[rblock]
        for _def in rcontext.defined:
          r = self.is_restored(_def.loc)
          if r:
            if r in restored_grouped.keys():
              restored_grouped[r].append(_def.loc)
            else:
              restored_grouped[r] = [_def.loc]

    restored = {}
    for r, locs in restored_grouped.iteritems():
      if len(locs) == len(return_blocks):
        for loc in locs:
          restored[loc] = r

    return restored

  def spoiled_locations(self):
    """ all registers and stack locations that are
        assigned but not restored """
    return

  def simplify(self):
    """ propagate phi groups that only have one item in them
        while keeping the ssa form. """
    p = phi_propagator_t(self)
    p.propagate()
    self.verify()
    return

  def remove_ssa_form(self):
    """ transform the function out of ssa form. """
    t = ssa_back_transformer_t(self.function)
    t.transform()
    return

  def verify_definition_has_use(self, defn, wanted_use):
    for use in defn.uses:
      if use is wanted_use:
        return True
    raise RuntimeError("%s was not a use of its definition:\n  def: %s\n  use: %s" % (repr(wanted_use.parent), repr(defn.parent_statement), repr(wanted_use.parent_statement)))

  def verify(self):
    """ verify that the ssa form is coherent. """
    for op in iterators.operand_iterator_t(self.function):
      if not isinstance(op, assignable_t):
        continue

      if op.definition:
        self.verify_definition_has_use(op.definition, op)
        assert op.definition.parent_statement, "%s: has a definition which is unlinked from the tree\n  def: %s" % (repr(op), repr(op.definition))
        assert op.definition.parent_statement.container, "%s: has a definition which is unlinked from the tree" % (repr(op), )

      for use in op.uses:
        assert use.definition, '%s: has a use without definition'
        assert use.definition is op, '%s: has a use that points to another definition\n  use: %s\n  wrong def: %s\n  should be: %s' % (repr(op), repr(use.parent_statement), repr(use.definition.parent_statement), repr(op.parent_statement))
        assert use.parent_statement, "%s: has a use (%s) which is unlinked from the tree" % (repr(op), repr(use))
        assert use.parent_statement.container, "%s: has a use (%s) which is unlinked from the tree" % (repr(op), repr(use))
    return

class live_range_t(object):
  """ """

  def __init__(self, function):
    self.function = function
    self.done = []
    self.block_to_defs = {}
    self.block_to_uses = {}
    self.stmt_to_expr = {}
    self.expr_to_stmt = {}
    self.process()
    return

  def process(self):
    current = {}
    self.process_block(self.function.entry_block, current)
    return

  def process_block(self, block, current):
    self.done.append(block)
    self.block_to_uses[block] = []
    self.block_to_defs[block] = []
    stmts = list(block.container)
    for stmt in stmts:
      if not stmt.expr:
        continue
      lives = [op for op in stmt.expr.iteroperands() if isinstance(op, assignable_t)]
      self.stmt_to_expr[stmt] = list(lives)
      self.block_to_uses[block] += [live for live in lives if not live.is_def]
      self.block_to_defs[block] += [live for live in lives if live.is_def]
      for live in lives:
        if live.is_def:
          if live not in self.expr_to_stmt:
            self.expr_to_stmt[live] = [stmt]
          else:
            self.expr_to_stmt[live].append(stmt)
          current[live] = []
        else:
          if live not in self.expr_to_stmt:
            self.expr_to_stmt[live] = stmts[:stmts.index(stmt)+1]
          else:
            _current = current[live] if live in current else []
            self.expr_to_stmt[live] += _current + [stmt]
          current[live] = []
        if isinstance(live.parent, phi_t):
          del current[live]
      for expr in current.keys():
        if expr not in lives:
          current[expr].append(stmt)
    for next_block in block.jump_to:
      if next_block not in self.done:
        self.process_block(next_block, current.copy())
      else:
        for expr in set(current.keys()):
          if expr in self.block_to_uses[next_block] and expr not in self.block_to_defs[next_block]:
            self.expr_to_stmt[expr] += current[expr]
            current[expr] = []
    return

class phi_propagator_t(propagator.propagator_t):
  """ Propagate phi-functions which alias to one and only one location.
      The program flow is still in SSA form after this propagation, but
      simple due to extra phi-functions being removed. """

  def __init__(self, ssa):
    propagator.propagator_t.__init__(self, ssa.function)
    self.ssa = ssa

  def replace_with(self, defn, value, use):
    if isinstance(value, phi_t) and len(value) == 1:
      return value[0]

  def replace(self, defn, value, use):
    for block, phis in self.ssa.block_phis.iteritems():
      stmt = defn.parent_statement
      if stmt in phis:
        phis.remove(stmt)
    phi = use.parent
    already_present = isinstance(phi, phi_t) and value in list(phi.operands)
    same_as_source = isinstance(phi, phi_t) and \
        isinstance(phi.parent_statement.expr, assign_t) and \
        phi.parent_statement.expr.op1 == value
    if already_present or same_as_source:
      use.definition = None
      if len(defn.uses) == 0:
        defn.parent_statement.expr.unlink()
        defn.parent_statement.remove()
      phi.remove(use)
      new = None
    else:
      new = propagator.propagator_t.replace(self, defn, value, use)
    return new

class ssa_back_transformer_t(object):
  """ Transform the function out of SSA form by inserting
      copy statements where appropriate. """

  def __init__(self, function):
    self.function = function
    self.var_n = 0
    self.live_range = live_range_t(function)
    return

  def live_range_without_definition(self, op, phi):
    return [x for x in self.live_range.expr_to_stmt[op] if x != phi.parent_statement and not (isinstance(x.expr, assign_t) and x.expr.op1 == op)]

  def intersection(self, op1, op2, phi):
    first = self.live_range_without_definition(op1, phi)
    second = self.live_range_without_definition(op2, phi)
    intersection = set([id(x) for x in first]).intersection(set([id(x) for x in second]))
    return intersection

  def insersect_with_group(self, group, expr, phi):
    for this in group:
      intersection = self.intersection(this, expr, phi)
      if len(intersection) > 0:
        return True
    return False

  def append_appropriate_group(self, groups, expr, phi):
    for group in groups:
      if not self.insersect_with_group(group, expr, phi):
        group.append(expr)
        return
    groups.append([expr])
    return

  def find_intersection_groups(self, expr):
    pool = list(expr.operands)
    groups = []
    while len(pool) > 0:
      this = pool.pop(0)
      self.append_appropriate_group(groups, this, expr)
    return groups

  def replace_uses(self, expr, new):
    expr.replace(new.copy())
    for use in expr.uses:
      use.replace(new.copy())

  def rename_groups(self, phi, groups):

    if len(groups) == 1:
      if type(phi.parent) == assign_t:
        if not self.insersect_with_group(groups[0], phi.parent.op1, phi):
          var = phi.parent.op1
          phi.parent_statement.remove()
        else:
          name = 'v%u' % (self.var_n, )
          self.var_n += 1
          var = var_t(None, name=name)
          phi.replace(var.copy())
      else:
        name = 'v%u' % (self.var_n, )
        self.var_n += 1
        var = var_t(None, name=name)
        phi.replace(var.copy())
      for _expr in groups[0]:
        self.replace_uses(_expr.definition, var)
    else:
      print 'more than one group'
      raise 'not implemented'

    return

  def transform(self):
    # insert copy statements for phi expressions
    for phi in iterators.operand_iterator_t(self.function, klass=phi_t):
      groups = self.find_intersection_groups(phi)
      self.rename_groups(phi, groups)

    # clear indices from all operands, remove def-use chains
    for op in iterators.operand_iterator_t(self.function, klass=assignable_t):
      op.index = None
      op.unlink()

    return
