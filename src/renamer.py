import iterators

from statements import *
from expressions import *

class renamer_t(object):
  """ rename locations """

  def __init__(self, function):
    self.function = function
    return

  def rename(self):
    for op in iterators.operand_iterator_t(self.function, filter=self.should_rename):
      new = self.rename_with(op)
      op.replace(new)
      op.unlink()
    # clear out phi statements with operands that do not have indexes anymore.
    for phi in iterators.operand_iterator_t(self.function, klass=phi_t):
      for op in list(phi.operands):
        if op.index is None:
          phi.remove(op)
          op.unlink()
    for stmt in iterators.statement_iterator_t(self.function):
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

    if expr in self.function.uninitialized:
      restored = self.is_restored(expr)
      if not restored or len(expr.uses) > 0:
        return True

    if isinstance(expr, assignable_t) and expr.definition:
      if expr.definition in self.function.uninitialized and len(expr.definition.uses) > 1:
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

    if expr in self.function.uninitialized:
      restored = self.is_restored(expr)
      if not restored or len(expr.uses) > 0:
        return True

    if isinstance(expr, assignable_t) and  expr.definition:
      if expr.definition in self.function.uninitialized:
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
    if type(expr.parent) is deref_t:
      return False

    in_phi = type(expr.parent) is phi_t
    if self.function.arch.is_stackreg(expr) and not expr.is_def:
      return not in_phi
    if self.function.arch.is_stackvar(expr):
      return not in_phi and isinstance(expr, add_t)

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

    var = stack_var_t(loc)

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
