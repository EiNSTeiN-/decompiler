from expressions import *
from iterators import *
import filters.simplify_expressions

class propagator_t(object):

  def __init__(self, function):
    self.function = function
    return

  def is_assignment(self, stmt):
    return isinstance(stmt.expr, assign_t) and \
        isinstance(stmt.expr.op1, assignable_t)
    return False

  def replace(self, defn, value, use):
    new = value.copy(with_definition=True)
    use.unlink()
    use.replace(new)
    if len(defn.uses) == 0:
      defn.parent_statement.expr.unlink()
      defn.parent_statement.remove()
    return new

  def propagate_single(self):
    propagated = False
    for stmt in statement_iterator_t(self.function):
      if not self.is_assignment(stmt):
        continue
      defn = stmt.expr.op1
      value = stmt.expr.op2
      for use in defn.uses[:]:
        new = self.replace_with(defn, value, use)
        if not new:
          continue
        newuse = self.replace(defn, new, use)
        if newuse:
          filters.simplify_expressions.run(newuse.parent_statement.expr, deep=True)
        propagated = True

    return propagated

  def propagate(self):
    while self.propagate_single():
      pass
    return

class phi_propagator_t(propagator_t):
  """ Propagate phi-functions which alias to one and only one location.
      The program flow is still in SSA form after this propagation, but
      simple due to extra phi-functions being removed. """

  def replace_with(self, defn, value, use):
    if isinstance(value, phi_t) and len(value) == 1:
      return value[0]

  def replace(self, defn, value, use):
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
      use.unlink()
      phi.remove(use)
      new = None
    else:
      new = propagator_t.replace(self, defn, value, use)
    return new

class stack_propagator_t(propagator_t):
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

class registers_propagator_t(propagator_t):
  def replace_with(self, defn, value, use):
    if isinstance(use, regloc_t) and not isinstance(use.parent, phi_t):
      return value

class call_arguments_propagator_t(propagator_t):
  def replace_with(self, defn, value, use):
    if len(defn.uses) > 1:
      return
    if isinstance(use.parent, params_t) and not isinstance(value, phi_t):
      return value
