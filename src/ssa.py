""" Transform a function into and out of SSA form.

"""

import propagator
import iterators

from statements import *
from expressions import *

import filters.simplify_expressions

class ssa_context_t(object):
  """ the context holds live locations at any given point in time.
      it is used by the tagger to find live uses during tagging. """

  def __init__(self, block, parent=None):
    self.block = block
    self.parent = parent
    self.defined = []
    return

  def get_local_definition(self, expr):
    for _loc in self.defined:
      if _loc.no_index_eq(expr):
        return _loc

  def get_recursive_definition(self, expr):
    loc = self.get_local_definition(expr)
    if loc:
      return loc
    if self.parent:
      return self.parent.get_recursive_definition(expr)

  def assign(self, expr):
    obj = self.get_local_definition(expr)
    if obj:
      self.defined.remove(obj)
    self.defined.append(expr)
    return

class ssa_contextual_iterator_t(object):

  def __init__(self, function, selector):
    self.function = function
    self.selector = selector
    self.done_blocks = []
    return

  def definitions(self, expr):
    return [op for op in expr.iteroperands() if self.selector(op) and op.is_def]

  def uses(self, expr):
    return [op for op in expr.iteroperands() if self.selector(op) and not op.is_def]

  def assign_definitions(self, context, expr):
    for op in self.definitions(expr):
      context.assign(op)
    return

  def traverse(self, context):
    if context.block in self.done_blocks:
      return
    self.done_blocks.append(context.block)
    for stmt in list(context.block.container.statements):
      self.statement(context, stmt)
    return

  def statement(self, context, stmt):
    for expr in stmt.expressions:
      self.assign_definitions(context, expr)

    if type(stmt) == goto_t and stmt.is_known() and \
          stmt.expr.value in self.function.blocks:
      target = self.function.blocks[stmt.expr.value]
      self.traverse(ssa_context_t(target, context))
    elif type(stmt) == branch_t:
      for expr in (stmt.true, stmt.false):
        target = self.function.blocks[expr.value]
        if target:
          self.traverse(ssa_context_t(target, context))
    return

class ssa_phase1_t(ssa_contextual_iterator_t):
  """ phase 1: collect live assignments at the end of each block """

  def __init__(self, function, selector):
    ssa_contextual_iterator_t.__init__(self, function, selector)
    self.exit_contexts = {}
    return

  def traverse(self, context):
    seen = context.block in self.done_blocks
    ssa_contextual_iterator_t.traverse(self, context)
    if not seen:
      self.exit_contexts[context.block] = context
    return

class ssa_phase2_t(ssa_contextual_iterator_t):
  """ phase 2: for each start of block, add phi statements where necessary """

  def __init__(self, function, selector, exit_contexts):
    ssa_contextual_iterator_t.__init__(self, function, selector)
    self.exit_contexts = exit_contexts
    self.index = 0
    return

  def entry_contexts(self, block):
    return [self.exit_contexts[_from] for _from in block.jump_from]

  def indexify(self, expr):
    if expr.index is None:
      expr.index = self.index
      self.index += 1
    return expr

  def find_uninitialized(self, use):
    """ if use is present in uninitialized, return it """
    for _def in self.function.uninitialized:
      if use.no_index_eq(_def):
        return _def
    return

  def insert_exit_definition(self, context, _def):
    ctx = self.exit_contexts[context.block]
    other_def = ctx.get_local_definition(_def)
    if not other_def or other_def.parent_statement.index() < _def.parent_statement.index():
      ctx.assign(_def)

    other_def = context.get_local_definition(_def)
    if not other_def:
      context.assign(_def)
    return

  def create_phi(self, context, use):
    pstmt = use.parent_statement
    block = context.block

    _def = use.copy(with_definition = True)
    _def.definition = None
    _def.index = None
    self.indexify(_def)

    phi = phi_t()
    stmt = statement_t(block.ea, assign_t(_def, phi))
    self.insert_exit_definition(context, _def)

    index = pstmt.index() if use.parent_statement.container.block is block else 0
    block.container.insert(index, stmt)

    return stmt, phi

  def create_uninitialized(self, use):
    self.indexify(use)
    copy = use.copy(with_definition=True)
    copy.definition = None
    copy.is_def = True
    copy.is_uninitialized = True
    self.function.uninitialized.append(copy)
    return copy

  def fetch_recursive_definitions_for_contexts(self, contexts, use):
    external_defs = list()
    for context in contexts:
      _def = self.fetch_recursive_definition(context, use)
      self.indexify(_def)
      if _def not in external_defs:
        external_defs.append(_def)
    return external_defs

  def fetch_recursive_definition(self, context, use):

    _def = context.get_local_definition(use)
    if _def:
      return _def

    contexts = self.entry_contexts(context.block)

    if len(contexts) == 0:
      # we've reached a block with no parent, which means
      # the use is uninitialized on this path.
      _def = self.find_uninitialized(use)
      if _def is None:
        _def = self.create_uninitialized(use)
      return _def

    stmt, phi = self.create_phi(context, use)
    external_defs = self.fetch_recursive_definitions_for_contexts(contexts, use)
    for _def in external_defs:
      copy = _def.copy(with_definition = True)
      copy.definition = _def
      copy.index = _def.index
      phi.append(copy)

    if len(stmt.expr.op2) == 0:
      raise RuntimeError('something might be wrong, the definition for %s is an empty phi-statement' % (stmt.expr.op1, ))

    return stmt.expr.op1

  def process_use(self, context, stmt, use):
    """ Process a single use of an expression.
    There are basically two cases:
      1. locally defined in this block
      2. externally defined in zero or more entry contexts.

    If a use is not defined in all entry contexts, it means there
    exists a path into this block where the expression is not defined,
    so the expression is external to the function on that path.
    """

    if use.definition:
      return

    _def = self.fetch_recursive_definition(context, use)
    self.indexify(_def)
    use.definition = _def
    use.index = _def.index

    return

  def statement(self, context, stmt):
    for expr in stmt.expressions:
      for use in self.uses(expr):
        if use.definition is None:
          self.process_use(context, stmt, use)
      for _def in self.definitions(expr):
        if _def.index is None:
          self.indexify(_def)
    ssa_contextual_iterator_t.statement(self, context, stmt)
    return

class live_range_t(object):
  """ Live range object contains references to each
      statements where the definition is "live". """

  def __init__(self, expr, live_blocks):
    # expression which starts the live range
    if expr.is_def:
      self.definition = expr
      self.definition_stmt = expr.parent_statement

      # definition is uninitialized in this function
      self.is_uninitialized = False

      # expression which stops the live range
      self.use = None
      self.use_stmt = None
    else:
      self.definition = expr.definition
      self.definition_stmt = expr.definition.parent_statement

      # definition is uninitialized in this function
      self.is_uninitialized = self.definition.is_uninitialized

      # expression which stops the live range
      self.use = expr
      self.use_stmt = expr.parent_statement

    # all blocks that are part of the path from the definition to the use.
    self.live_blocks = live_blocks
    return

  @property
  def statements(self):
    """ return all statements that are part of the live range,
        from assignment to the use. """
    if self.use is None:
      return [self.definition_stmt]

    end = self.live_blocks[-1]
    if self.is_uninitialized:
      start = None
      intermediates = self.live_blocks[:-1]
    else:
      start = self.live_blocks[0]
      intermediates = self.live_blocks[1:-1]

    stmts = []
    if start is end:
      if self.definition_stmt.index() >= self.use_stmt.index():
        # def is after use
        for stmt in start.container[self.definition_stmt.index():]:
          stmts.append(stmt)
        for stmt in start.container[:self.use_stmt.index()+1]:
          stmts.append(stmt)
      else:
        # use is after def
        for stmt in start.container[self.definition_stmt.index():self.use_stmt.index()+1]:
          stmts.append(stmt)
    else:
      if start:
        for stmt in start.container[self.definition_stmt.index():]:
          stmts.append(stmt)
      for block in intermediates:
        for stmt in block.container:
          stmts.append(stmt)
      for stmt in end.container[:self.use_stmt.index()+1]:
        stmts.append(stmt)
    return stmts

class live_range_iterator_t(ssa_phase1_t):
  """ Iterates over the function statements and determines the live
      range of each assignments. """

  def __init__(self, function):
    ssa_phase1_t.__init__(self, function, lambda loc: isinstance(loc, assignable_t))
    self.all_uses = []
    return

  def entry_contexts(self, block):
    return [self.exit_contexts[_from] for _from in block.jump_from]

  def parent_context_iterator(self, context):
    yield context
    parent = context.parent
    while parent:
      yield parent
      parent = parent.parent
    return

  def live_blocks_for_use(self, use):
    block = use.parent_statement.container.block
    contexts = self.entry_contexts(block)
    live_blocks = [block]
    for context in contexts:
      if not use.is_def and use.definition and use.definition.is_uninitialized:
        for parent in self.parent_context_iterator(context):
          if parent.block not in live_blocks:
            live_blocks.append(parent.block)
        continue
      r = context.get_recursive_definition(use)
      if not r or r.index != use.index:
        continue
      for parent in self.parent_context_iterator(context):
        if parent.block not in live_blocks:
          live_blocks.append(parent.block)
        if parent.get_local_definition(use):
          break
    return list(reversed(live_blocks))

  def live_ranges(self):
    self.traverse(ssa_context_t(self.function.entry_block))
    live_ranges = []
    for use in self.all_uses:
      live_blocks = self.live_blocks_for_use(use)
      live_ranges.append(live_range_t(use, live_blocks))
    return live_ranges

  def statement(self, context, stmt):
    for expr in stmt.expressions:
      self.all_uses += self.uses(expr)
      self.all_uses += [defn for defn in self.definitions(expr) if len(defn.uses) == 0]
    ssa_phase1_t.statement(self, context, stmt)
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

    # list of `assignable_t` that are _never_ defined anywhere within
    # the scope of this function.
    #self.__uninitialized = []

    # dict of `node_t` : [`expr_t`, ...]
    # contains contexts at the exit of each block.
    self.exit_contexts = {}

    return

  def tag_step(self, step, selector):
    self.done_blocks = []
    self.tagger_step = step

    p1 = ssa_phase1_t(self.function, selector)
    p1.traverse(ssa_context_t(self.function.entry_block))
    self.exit_contexts[self.tagger_step] = p1.exit_contexts

    p2 = ssa_phase2_t(self.function, selector, p1.exit_contexts)
    p2.index = self.index
    p2.traverse(ssa_context_t(self.function.entry_block))
    #self.__uninitialized += p2.uninitialized

    self.index = p2.index
    self.simplify()
    return

  def tag_registers(self):
    return self.tag_step(SSA_STEP_REGISTERS, lambda loc: isinstance(loc, regloc_t))

  def tag_derefs(self):
    return self.tag_step(SSA_STEP_DEREFERENCES, lambda loc: isinstance(loc, deref_t))

  def tag_arguments(self):
    return self.tag_step(SSA_STEP_ARGUMENTS, lambda loc: isinstance(loc, arg_t))

  def tag_variables(self):
    return self.tag_step(SSA_STEP_VARIABLES, lambda loc: isinstance(loc, var_t))

  def is_restored(self, expr):
    start = [expr]
    checked = [] # keep track of checked values to avoid recursion
    while len(start) > 0:
      current = start.pop(0)
      if not isinstance(current.parent, assign_t):
        continue
      rvalue = current.parent.op2
      if not isinstance(rvalue, assignable_t):
        continue
      if rvalue in list(self.function.uninitialized) and rvalue.no_index_eq(expr):
        return rvalue
      elif isinstance(rvalue, phi_t):
        for t in rvalue:
          if t in self.function.uninitialized:
            return t
          if t.definition and t.definition not in checked:
            start.append(t.definition)
      elif rvalue.definition:
        if rvalue.definition not in checked:
          start.append(rvalue.definition)
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
          r = self.is_restored(_def)
          if r:
            if r in restored_grouped.keys():
              restored_grouped[r].append(_def)
            else:
              restored_grouped[r] = [_def]

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

    p = propagator.phi_propagator_t(self.function)
    p.propagate()

    p = ssa_self_reference_propagator(self.function)
    p.run()

    p = ssa_chained_phi_propagator(self.function)
    p.run()

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
        assert op.is_def is False, "%s: expected is_def=False" % (repr(op), )
        self.verify_definition_has_use(op.definition, op)
        if not op.definition.is_uninitialized:
          stmt = op.definition.parent_statement
          assert stmt, "%s: has a definition which is unlinked from the tree\n  def: %s" % (repr(op), repr(op.definition))
          assert stmt is self.function.uninitialized_stmt or stmt.container, "%s: has a definition which is unlinked from the tree" % (repr(op), )
        assert op.definition.index == op.index, "%s: expected to have the same index as its definition: %s" % (op, op.definition)

      for use in op.uses:
        assert use.definition, '%s: has a use without definition'
        assert use.definition is op, '%s: has a use that points to another definition\n  use: %s\n  wrong def: %s\n  should be: %s' % (repr(op), repr(use.parent_statement), repr(use.definition.parent_statement), repr(op.parent_statement))
        stmt = use.parent_statement
        assert stmt, "%s: has a use (%s) which is unlinked from the tree" % (repr(op), repr(use))
        assert stmt is self.function.uninitialized_stmt or use.parent_statement.container, "%s: has a use (%s) which is unlinked from the tree" % (repr(op), repr(use))
        assert use.definition.index == use.index, "%s: expected to have the same index as its definition: %s" % (use.parent_statement, use.definition.parent_statement)
    return

class ssa_chained_phi_propagator(object):
  """ we have a phi definition that has only one use, and the
      use is within another phi-statement. we can propagate the
      definition and merge the phi-statements together. """

  def __init__(self, function):
    self.function = function
    return

  def run(self):
    while self.propagate():
      pass
    return

  def propagate(self):
    for stmt in iterators.statement_iterator_t(self.function):
      if type(stmt.expr) != assign_t:
        continue
      if isinstance(stmt.expr.op2, phi_t) and len(stmt.expr.op1.uses) == 1 and \
          isinstance(stmt.expr.op1.uses[0].parent, phi_t):
        use = stmt.expr.op1.uses[0]
        self.propagate_to(stmt.expr.op2, use.parent)
        use.unlink()
        use.parent.remove(use)
        stmt.expr.unlink()
        stmt.remove()
        return True

  def propagate_to(self, src, dest):
    for op in src:
      if op not in dest:
        dest.append(op.pluck())
    return

class ssa_self_reference_propagator(object):
  """ when we have phi that depends on itself plus some other
      expression, like: esp@22 = PHI(esp@18, esp@22, );
      we can replace esp@22 with esp@18 without problem. """

  def __init__(self, function):
    self.function = function
    return

  def run(self):
    while self.propagate():
      pass
    return

  def propagate(self):
    for stmt in iterators.statement_iterator_t(self.function):
      if type(stmt.expr) != assign_t:
        continue
      if isinstance(stmt.expr.op2, phi_t) and len(stmt.expr.op2) == 2:
        if stmt.expr.op1 == stmt.expr.op2[0]:
          self.propagate_to(stmt.expr.op1, stmt.expr.op2[1])
        elif stmt.expr.op1 == stmt.expr.op2[1]:
          self.propagate_to(stmt.expr.op1, stmt.expr.op2[0])
        else:
          continue
        stmt.expr.unlink()
        stmt.remove()
        return True

  def propagate_to(self, defn, expr):
    for use in defn.uses:
      copy = expr.copy(with_definition=True)
      use.replace(copy)
      use.unlink()
    return

class ssa_back_transformer_t(object):
  """ Transform the function out of SSA form by inserting
      copy statements where appropriate. """

  def __init__(self, function):
    self.function = function
    self.var_n = 0

    it = live_range_iterator_t(function)
    self.live_ranges = it.live_ranges()
    return

  def live_ranges_for(self, op):
    for lr in self.live_ranges:
      if lr.use == op:
        yield lr
    return

  def interfere(self, op1, op2):
    """ return intersecting statements between the live ranges of op1 and op2 """
    if op1.definition:
      for range1 in self.live_ranges_for(op1):
        for range2 in self.live_ranges_for(op2):
          if range1.definition.parent_statement is range2.use.parent_statement:
            continue
          if range1.definition.parent_statement in range2.statements:
            return True
    if op2.definition:
      for range1 in self.live_ranges_for(op1):
        for range2 in self.live_ranges_for(op2):
          if range2.definition.parent_statement is range1.use.parent_statement:
            continue
          if range2.definition.parent_statement in range1.statements:
            return True
    return False

  def insersect_with_group(self, group, expr, phi):
    """ return true if expr and phi intersect with each other. """
    for this in group:
      if self.interfere(this, expr):
        return True
    return False

  def add_to_appropriate_group(self, groups, expr, phi):
    """ find a non-interfering group or create a new group. """

    for group in groups:
      if not self.insersect_with_group(group, expr, phi):
        # found a non-interfering group for this expression.
        group.append(expr)
        return

    # add to its own new group.
    groups.append([expr])
    return

  def find_intersection_groups(self, phi):
    """ group non-interfering expressions together """
    pool = list(phi.operands)
    groups = []
    while len(pool) > 0:
      expr = pool.pop(0)
      self.add_to_appropriate_group(groups, expr, phi)
    return groups

  def replace_uses(self, expr, new):
    for use in expr.uses:
      use.replace(new.copy())
      use.unlink()
    expr.replace(new.copy())
    expr.unlink()

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
        if _expr.definition:
          self.replace_uses(_expr.definition, var)
      phi.unlink()
    else:
      print 'more than one group'
      print '   ', repr(groups)
      raise 'not implemented'

    return

  def transform(self):
    # insert copy statements for phi expressions
    for phi in iterators.operand_iterator_t(self.function, klass=phi_t):
      groups = self.find_intersection_groups(phi)
      self.rename_groups(phi, groups)

    # clear indices from all operands, remove def-use chains
    for arg in self.function.arguments:
      for op in arg.iteroperands():
        op.index = None
    for op in iterators.operand_iterator_t(self.function, klass=assignable_t):
      op.index = None

    return
