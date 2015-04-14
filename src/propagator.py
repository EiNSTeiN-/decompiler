from expressions import *
from iterators import *
import filters.simplify_expressions

class propagator_t(object):

  def __init__(self, flow):
    self.flow = flow
    return

  def is_assignment(self, stmt):
    return isinstance(stmt.expr, assign_t) and \
        isinstance(stmt.expr.op1, assignable_t)
    return False

  def copy_for_replace(self, source_expr):
    new = source_expr.copy(with_definition=True)
    return new

  def replace(self, defn, value, use):
    new = self.copy_for_replace(value)
    use.unlink()
    use.replace(new)
    if len(defn.uses) == 0:
      defn.parent_statement.expr.unlink()
      defn.parent_statement.remove()
    return new

  def propagate_single(self):
    propagated = False
    for stmt in statement_iterator_t(self.flow):
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
