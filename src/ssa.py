""" Transform the program flow in SSA form.

"""

from statements import *
from expressions import *

import filters.simplify_expressions

class defined_loc_t(object):

  def __init__(self, block, loc):
    self.block = block
    self.loc = loc
    self.cleanloc = loc.copy()
    self.cleanloc.index = None
    self.alt_forms = []
    self.find_alt()
    return

  def __eq__(self, other):
    return type(other) == defined_loc_t and other.loc.clean() == self.loc.clean()

  def __ne__(self, other):
    return not (self == other)

  def find_alt(self):
    cp = self.loc.copy()
    cp.index = None
    self.alt_forms = [cp.copy()]

    while True:
      replaced = False

      for alt in self.alt_forms[:]:
        for op in alt.iteroperands():
          if isinstance(op, deref_t):
            continue
          if isinstance(op, assignable_t) and op.definition:

            # get right side of assignment (assigned value)

            if not op.definition.is_def:
              continue

            value = op.definition.parent.op2

            if type(value) == theta_t:
              self.alt_forms.remove(alt)
              for thetaop in value:
                op.replace(thetaop.copy())
                if alt not in self.alt_forms:
                  self.alt_forms.append(alt.copy())
              replaced = True
              break
            else:
              op.replace(value.copy())
              replaced = True
              break
      if not replaced:
          break

    self.alt_forms = [filters.simplify_expressions.run(expr, deep=True) for expr in self.alt_forms]
    #for alt in self.alt_forms:
    #  alt.index = None

    self.alt_forms = [alt for alt in self.alt_forms if not alt.no_index_eq(cp)]

    return

class ssa_context_t(object):

  def __init__(self):
    self.defined = []
    return

  def copy(self):
    ctx = ssa_context_t()
    ctx.defined = self.defined[:]
    return ctx

  def get_definition(self, block, expr):
    obj = self.get_definition_object(block, expr)
    if obj:
      return obj.loc
    return

  def get_definition_object(self, block, expr):
    expr = expr.copy()
    expr.index = None
    loc = defined_loc_t(block, expr)

    for _loc in self.defined:
      if _loc.cleanloc == loc.cleanloc:
        return _loc

      for alt1 in loc.alt_forms:
        for alt2 in _loc.alt_forms:
          if alt1.clean() == alt2.clean():
            return _loc

    return

  def need_theta(self, block, expr):
    #~ print 'need theta?', repr(expr)
    obj = self.get_definition_object(block, expr)
    if obj:
      #~ print 'last def', repr(obj.loc)
      return obj.block != block
    #~ for _loc in self.defined:
      #~ if _loc.loc.clean() == expr.clean():
        #~ return _loc.block != block
    #~ print 'nope'
    return False

  def add_uninitialized_loc(self, block, expr):
    loc = defined_loc_t(block, expr)
    self.defined.append(loc)
    return

  def assign(self, block, expr):
    loc = defined_loc_t(block, expr)
    obj = self.get_definition_object(block, expr)
    if obj:
      self.defined.remove(obj)
    #~ for _loc in self.defined:
      #~ if _loc == loc:
        #~ self.defined.remove(_loc)
        #~ print 'reassign', repr(_loc.loc)
        #~ break

    self.defined.append(loc)
    return


SSA_STEP_NONE = 0
SSA_STEP_REGISTERS = 1
SSA_STEP_DEREFERENCES = 2

class ssa_tagger_t():
  """
  """

  def __init__(self, flow):
    self.flow = flow

    self.tagger_step = SSA_STEP_NONE

    self.index = 0

    # keep track of any block which we have already walked into, because at
    # this stage we may still encounter recursion (gotos that lead backwards).
    self.done_blocks = []

    # list of `assignable_t` that are _never_ defined anywhere within
    # the scope of this function.
    self.uninitialized = []

    #~ # map of `flowblock_t`: `ssa_block_contexts_t`. this is a copy of the
    #~ # context at each statement. this is useful when trying to
    #~ # determine if a register is restored or not, or which locations
    #~ # are defined at a specific location.
    #~ self.block_context = {}

    #~ # list of `statement_t`
    #~ self.theta_statements = []
    #~ # dict of `assignable_t`: `theta_t`
    #~ self.theta_map = {}

    # dict containing a starting expression as key and its
    # alternate forms: { `expr_t`: [`expr_t`, ...] }
    self.aliases = {}

    # dict of `flowblock_t` : [`expr_t`, ...]
    # contains contexts at the exit of each block.
    self.exit_defines = {}

    # dict of `flowblock_t` : [`expr_t`, ...]
    # contains each block and a list of thier theta assignments.
    self.block_thetas = {}

    return

  def is_correct_step(self, loc):

    if not isinstance(loc, assignable_t):
      return False

    if isinstance(loc, regloc_t) and self.tagger_step == SSA_STEP_REGISTERS:
      return True

    if isinstance(loc, deref_t) and self.tagger_step == SSA_STEP_DEREFERENCES:
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

  def insert_theta(self, block, lastdef, thisdef):

    newuse = self.clean_du(lastdef.copy())
    stmt = statement_t(assign_t(self.clean_du(thisdef.copy()), theta_t(newuse)))
    block.container.insert(thisdef.parent_statement.index(), stmt)

    if lastdef.is_def:
        self.link(lastdef, newuse)

    return stmt

  def tag_use(self, context, block, expr):
    if context.need_theta(block, expr):
      # expr is defined in another block.

      lastdef = context.get_definition(block, expr)
      if lastdef:
        stmt = self.insert_theta(block, lastdef, expr)

        self.block_thetas[block].append(stmt)

        context.assign(block, stmt.expr.op1)
        stmt.expr.op1.index = self.index
        self.index += 1

        expr.index = stmt.expr.op1.index
        self.link(stmt.expr.op1, expr)
        return

    lastdef = context.get_definition(block, expr)
    if lastdef:
      # the location is previously defined.
      expr.index = lastdef.index
      self.link(lastdef, expr)
    else:
      # the location is not defined, it's external to the function.
      self.tag_uninitialized(expr)
      context.add_uninitialized_loc(block, expr)

    return

  def link(self, d, u):
    d.uses.append(u)
    u.definition = d
    return

  def clean_du(self, loc):
    loc.uses = []
    loc.definition = None
    return loc

  def collect_aliases(self, block, expr):

    if not isinstance(expr, deref_t):
      return

    loc = defined_loc_t(block, expr)

    for alt in loc.alt_forms:
      found = False
      for alias in self.aliases:
        if alias == alt:
          if loc.cleanloc not in self.aliases[alias]:
            self.aliases[alias].append(loc.cleanloc)
          found = True
          break
      if not found:
        self.aliases[alt] = [loc.cleanloc]

    return

  def tag_block(self, context, block):

    if block in self.done_blocks:
      # insert new locations from the current context in all
      # theta-functions present in this block.
      for stmt in self.block_thetas[block]:
        loc = stmt.expr.op1
        lastdef = context.get_definition(block, loc)
        if lastdef and lastdef != loc:
          newuse = self.clean_du(lastdef.copy())
          stmt.expr.op2.append(newuse)
          self.link(lastdef, newuse)
      return

    self.done_blocks.append(block)
    self.block_thetas[block] = []

    for stmt in list(block.container.statements):
      for expr in stmt.expressions:
        # process uses for this statement
        uses = self.get_uses(expr)
        for use in uses:
          if use.index is None:
            self.tag_use(context, block, use)
            self.collect_aliases(block, use)

        # process defs for this statement
        defs = self.get_defs(expr)
        for _def in defs:
          context.assign(block, _def)
          _def.index = self.index
          self.index += 1
          self.collect_aliases(block, _def)

      if type(stmt) == goto_t:
        target = self.flow.get_block(stmt)
        self.tag_block(context.copy(), target)
      elif type(stmt) == branch_t:
        for expr in (stmt.true, stmt.false):
          target = self.flow.get_block(expr)
          if target:
            self.tag_block(context.copy(), target)
      elif type(stmt) == return_t:
        print 'return', repr(stmt)
        pass

    return

  def tag_registers(self):
    self.done_blocks = []
    self.tagger_step = SSA_STEP_REGISTERS
    context = ssa_context_t()
    self.tag_block(context, self.flow.entry_block)
    return

  def find_aliases(self):
    #~ s = expression_solver_t(self.flow)
    #~ self.aliases = s.find_deref_locations()
    #~ print 'ALIASES', repr(self.aliases)
    return

  def tag_derefs(self):
    self.done_blocks = []
    self.tagger_step = SSA_STEP_DEREFERENCES
    context = ssa_context_t()
    self.tag_block(context, self.flow.entry_block)
    return

  def tag(self):
    self.tag_registers()
    #self.find_aliases()
    self.tag_derefs()
    return

  #~ def has_internal_definition(self, stmt, loc):
    #~ """ check if `loc` is defined prior to `stmt` in the same block.
      #~ Returns a reference to the (properly indexed) definition of `loc`. """

    #~ for i in range(stmt.index(), -1, -1):
      #~ _stmt = stmt.container[i]
      #~ if type(_stmt) == statement_t and type(_stmt.expr) == assign_t and \
          #~ _stmt.expr.op1.clean() == loc.clean():
        #~ return _stmt.expr.op1

    #~ return

  #~ def has_contextual_definition(self, stmt, loc):
    #~ """ check if `loc` is defined in all paths leading to this block. """
    #~ return False



