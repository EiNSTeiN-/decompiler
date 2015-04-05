""" This module runs an expression through a series of filters.

When a filter matches, a new expression is created from the old one
and returned to the caller, which should call again until all filters
are exhausted and no simpler expression can be generated.
"""

from expressions import *

__all__ = []

def flags(expr):
  """ transform flags operations into simpler expressions such as lower-than
      or greater-than.

  unsigned stuff:
  CARRY(a - b) becomes a < b
  !CARRY(a - b) becomes a > b

  signed stuff:
  SIGN(a - b) != OVERFLOW(a - b) becomes a < b
  SIGN(a - b) == OVERFLOW(a - b) becomes a > b

  and for both:
  !(a - b) || a < b becomes a <= b
  (a - b) && a > b becomes a >= b

  """

  is_less = lambda expr: type(expr) == neq_t and \
        type(expr.op1) == sign_t and type(expr.op2) == overflow_t and \
        expr.op1.op == expr.op2.op #and type(expr.op1.op) == sub_t
  is_greater = lambda expr: type(expr) == eq_t and \
        type(expr.op1) == sign_t and type(expr.op2) == overflow_t and \
        expr.op1.op == expr.op2.op #and type(expr.op1.op) == sub_t

  is_lower = lambda expr: type(expr) == carry_t #and type(expr.op) == sub_t
  is_above = lambda expr: type(expr) == b_not_t and is_lower(expr.op)

  is_leq = lambda expr: type(expr) == b_or_t and type(expr.op1) == b_not_t and \
              type(expr.op2) == lower_t and expr.op1.op == expr.op2
  is_aeq = lambda expr: type(expr) == b_and_t and \
              type(expr.op2) in (above_t, aeq_t) and expr.op1 == expr.op2.op1

  # signed less-than
  if is_less(expr):
    return lower_t(expr.op1.op.copy(), value_t(0, expr.op1.op.size))

  # signed greater-than
  if is_greater(expr):
    return above_t(expr.op1.op.copy(), value_t(0, expr.op1.op.size))

  # unsigned lower-than
  if is_lower(expr):
    return lower_t(expr.op.copy(), value_t(0, expr.op.size))

  # unsigned above-than
  if is_above(expr):
    return above_t(expr.op.op.copy(), value_t(0, expr.op.op.size))

  # less-or-equal
  if is_leq(expr):
    return leq_t(expr.op2.copy(), value_t(0, expr.op2.size))

  # above-or-equal
  if is_aeq(expr):
    return aeq_t(expr.op1.copy(), value_t(0, expr.op1.size))

  return
__all__.append(flags)

def add_sub(expr):
  """ Simplify nested math expressions when the second operand of
      each expression is a number literal.

  (a +/- n1) +/- n2 => (a +/- n3) with n3 = n1 +/- n2
  (a +/- 0) => a
  """

  if expr.__class__ == add_t and expr.op1.__class__ in (add_t, sub_t) \
        and expr.op1.op2.__class__ == value_t and expr.op2.__class__ == value_t:
    _expr = expr.op1.copy()
    _expr.add(expr.op2)
    return _expr

  if expr.__class__ == sub_t and expr.op1.__class__ in (add_t, sub_t) \
        and expr.op1.op2.__class__ == value_t and expr.op2.__class__ == value_t:
    _expr = expr.op1.copy()
    _expr.sub(expr.op2)
    return _expr

  if type(expr) in (sub_t, add_t):
    if type(expr.op2) == value_t and expr.op2.value == 0:
      return expr.op1.copy()

  if expr.__class__ == add_t and expr.op1.__class__ == value_t \
        and expr.op2.__class__ == value_t:
    _expr = value_t(expr.op1.value + expr.op2.value, expr.op1.size)
    return _expr

  if expr.__class__ == sub_t and expr.op1.__class__ == value_t \
        and expr.op2.__class__ == value_t:
    _expr = value_t(expr.op1.value - expr.op2.value, expr.op1.size)
    return _expr

  return
__all__.append(add_sub)

def ref_deref(expr):
  """ remove nested deref_t and address_t that cancel each other

  &(*(addr)) => addr
  *(&(addr)) => addr
  """

  if type(expr) == address_t and type(expr.op) == deref_t:
    return expr.op.op.copy()

  if type(expr) == deref_t and type(expr.op) == address_t:
    return expr.op.op.copy()

  return
__all__.append(ref_deref)

def equality_with_literals(expr):
  """ Applies commutativity of equality (==) sign

  (<1> - n1) == n2 becomes <1> == n3 where n3 = n1 + n2
  """

  if type(expr) in (eq_t, neq_t, above_t, lower_t, aeq_t, leq_t) and type(expr.op2) == value_t and \
    type(expr.op1) in (sub_t, add_t) and type(expr.op1.op2) == value_t:

    if type(expr.op1) == sub_t:
      _value = value_t(expr.op2.value + expr.op1.op2.value, max(expr.op2.size, expr.op1.op2.size))
    else:
      _value = value_t(expr.op2.value - expr.op1.op2.value, max(expr.op2.size, expr.op1.op2.size))
    return expr.__class__(expr.op1.op1.copy(), _value)

  return
__all__.append(equality_with_literals)

def negate(expr):
  """ transform negations into simpler, more readable forms

  !(a && b) becomes !a || !b
  !(a || b) becomes !a && !b
  !(a == b) becomes a != b
  !(a != b) becomes a == b
  !(!(expr)) becomes expr
  a == 0 becomes !a

  !(a < b) becomes a >= b
  !(a > b) becomes a <= b
  !(a >= b) becomes a < b
  !(a <= b) becomes a > b
  """

  if type(expr) == b_not_t and type(expr.op) == b_and_t:
    return b_or_t(b_not_t(expr.op.op1.copy()), b_not_t(expr.op.op2.copy()))

  if type(expr) == b_not_t and type(expr.op) == b_or_t:
    return b_and_t(b_not_t(expr.op.op1.copy()), b_not_t(expr.op.op2.copy()))

  if type(expr) == b_not_t and type(expr.op) == eq_t:
    return neq_t(expr.op.op1.copy(), expr.op.op2.copy())

  if type(expr) == b_not_t and type(expr.op) == neq_t:
    return eq_t(expr.op.op1.copy(), expr.op.op2.copy())

  if type(expr) == b_not_t and type(expr.op) == b_not_t:
    return expr.op.op.copy()

  if type(expr) == eq_t and type(expr.op2) == value_t and expr.op2.value == 0:
    return b_not_t(expr.op1.copy())

  # !(a < b) becomes a >= b
  if type(expr) == b_not_t and type(expr.op) == lower_t:
    return aeq_t(expr.op.op1.copy(), expr.op.op2.copy())

  # !(a > b) becomes a <= b
  if type(expr) == b_not_t and type(expr.op) == above_t:
    return leq_t(expr.op.op1.copy(), expr.op.op2.copy())

  # !(a >= b) becomes a < b
  if type(expr) == b_not_t and type(expr.op) == aeq_t:
    return lower_t(expr.op.op1.copy(), expr.op.op2.copy())

  # !(a <= b) becomes a > b
  if type(expr) == b_not_t and type(expr.op) == leq_t:
    return above_t(expr.op.op1.copy(), expr.op.op2.copy())

  return
__all__.append(negate)

def correct_signs(expr):
  """ substitute addition or substraction by its inverse depending on the operand sign

  x + -y becomes x - y
  x - -y becomes x + y
  """

  if type(expr) == add_t and type(expr.op2) == value_t and expr.op2.value < 0:
    return sub_t(expr.op1.copy(), value_t(abs(expr.op2.value), expr.op2.size))

  if type(expr) == sub_t and type(expr.op2) == value_t and expr.op2.value < 0:
    return add_t(expr.op1.copy(), value_t(abs(expr.op2.value), expr.op2.size))

  return
__all__.append(correct_signs)

def special_xor(expr):
  """ transform xor_t into a literal 0 if both operands to the xor are the same

  x ^ x becomes 0
  """

  if type(expr) == xor_t and expr.op1 == expr.op2:
    return value_t(0, expr.op1.size)

  return
__all__.append(special_xor)

def special_and(expr):
  """ transform the and (&) operator into a simpler form in the special case
  that both operands are the same

  x & x becomes x
  """

  if type(expr) == and_t and expr.op1 == expr.op2:
    return expr.op1.copy()

  return
__all__.append(special_and)

def once(expr, deep=False):
  """ run all filters and return the first available simplification """

  for filter in __all__:
    newexpr = filter(expr)
    if newexpr:
      if expr.parent:
        expr.replace(newexpr)
      return newexpr

  if deep and isinstance(expr, expr_t):
    for op in expr.operands:
      newexpr = once(op, deep)
      if newexpr:
        return expr

  return

def run(expr, deep=False):
  """ combine expressions until they cannot be combined any more.
      return the new expression. """

  while True:
    newexpr = once(expr, deep=deep)
    if not newexpr:
      break
    expr = newexpr

  return expr
