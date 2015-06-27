import iterators
from expressions import *

class pruner_t(object):

  def __init__(self, dec):
    self.dec = dec
    self.function = dec.function
    return

  def is_prunable(self, stmt):
    return False

  def remove(self, stmt):
    stmt.expr.unlink()
    stmt.remove()
    return

  def prune(self):
    while True:
      pruned = False
      for stmt in iterators.statement_iterator_t(self.function):
        if not self.is_prunable(stmt):
          continue
        pruned = True
        self.remove(stmt)
      if not pruned:
        break
    return

class unused_registers_pruner_t(pruner_t):

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if isinstance(stmt.expr.op2, call_t):
      return False
    if not isinstance(stmt.expr.op1, assignable_t):
      return False
    if not isinstance(stmt.expr.op1, regloc_t):
      return False
    if stmt.expr.op1.index is None:
      return False
    if len(stmt.expr.op1.uses) > 0:
      return False
    return True

class restored_locations_pruner_t(pruner_t):

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if stmt.expr.op2 not in self.dec.restored_locations.values():
      return False
    return len(stmt.expr.op1.uses) == 0

class unused_call_returns_pruner_t(pruner_t):

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if not isinstance(stmt.expr.op2, call_t):
      return False
    if len(stmt.expr.op1.uses) > 0:
      return False
    return True

  def remove(self, stmt):
    old = stmt.expr
    stmt.expr = stmt.expr.op2.pluck()
    old.unlink()
    return

class unused_stack_locations_pruner_t(pruner_t):

  def is_prunable(self, stmt):
    if not isinstance(stmt.expr, assign_t):
      return False
    if isinstance(stmt.expr.op2, call_t):
      return False
    if not isinstance(stmt.expr.op1, assignable_t):
      return False
    if not isinstance(stmt.expr.op1, stack_var_t):
      return False
    if stmt.expr.op1.index is None:
      return False
    if len(stmt.expr.op1.uses) > 0:
      return False
    return True
