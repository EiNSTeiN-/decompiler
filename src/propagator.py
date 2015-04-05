from expressions import *
from iterators import *

class propagator_t(object):

  def __init__(self, flow):
    self.flow = flow
    return

  def is_assignment(self, stmt):
    return isinstance(stmt.expr, assign_t) and \
        isinstance(stmt.expr.op1, assignable_t)
    return False

  def copy_for_replace(self, source_expr):
    new = source_expr.copy()
    for expr in new.iteroperands():
      if not isinstance(expr, assignable_t):
        continue
      if expr.definition:
        expr.definition.uses.append(expr)
    return new

  def replace(self, defn, value, use):
    use.replace(self.copy_for_replace(value))
    defn.uses.remove(use)
    if len(defn.uses) == 0:
      defn.parent_statement.remove()

  def propagate(self):
    for stmt in statement_iterator_t(self.flow):
      if not self.is_assignment(stmt):
        continue
      defn = stmt.expr.op1
      value = stmt.expr.op2
      for use in defn.uses[:]:
        new = self.replace_with(defn, value, use)
        if new:
          self.replace(defn, new, use)
    return
