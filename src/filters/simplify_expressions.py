""" This module runs an expression through a series of filters.

When a filter matches, a new expression is created from the old one
and returned to the caller, which should call again until all filters
are exhausted and no simpler expression can be generated.
"""

from expressions import *

__all__ = []

def simplifier(func):
  __all__.append(func)

@simplifier
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
    op = expr.op1.op

  # signed greater-than
  elif is_greater(expr):
    op = expr.op1.op

  # unsigned lower-than
  elif is_lower(expr):
    op = expr.op

  # unsigned above-than
  elif is_above(expr):
    op = expr.op.op

  # less-or-equal
  elif is_leq(expr):
    op = expr.op2

  # above-or-equal
  elif is_aeq(expr):
    op = expr.op1

  else:
    return

  return lower_t(op.pluck(), value_t(0, op.size))

@simplifier
def add_sub(expr):
  """ Simplify nested math expressions when the second operand of
      each expression is a number literal.

  (a +/- n1) +/- n2 => (a +/- n3) with n3 = n1 +/- n2
  (a +/- 0) => a
  """

  if type(expr) == add_t and type(expr.op1) in (add_t, sub_t) \
        and type(expr.op1.op2) == value_t and type(expr.op2) == value_t:
    _expr = expr.op1.pluck()
    _expr.add(expr.op2)
    return _expr

  if type(expr) == sub_t and type(expr.op1) in (add_t, sub_t) \
        and type(expr.op1.op2) == value_t and type(expr.op2) == value_t:
    _expr = expr.op1.pluck()
    _expr.sub(expr.op2)
    return _expr

  if type(expr) in (sub_t, add_t):
    if type(expr.op2) == value_t and expr.op2.value == 0:
      return expr.op1.pluck()

  if type(expr) == add_t and type(expr.op1) == value_t \
        and type(expr.op2) == value_t:
    _expr = value_t(expr.op1.value + expr.op2.value, expr.op1.size)
    return _expr

  if type(expr) == sub_t and type(expr.op1) == value_t \
        and type(expr.op2) == value_t:
    _expr = value_t(expr.op1.value - expr.op2.value, expr.op1.size)
    return _expr

  return

@simplifier
def ref_deref(expr):
  """ remove nested deref_t and address_t that cancel each other

  &(*(addr)) => addr
  *(&(addr)) => addr
  """

  if type(expr) == address_t and type(expr.op) == deref_t:
    return expr.op.op.pluck()

  if type(expr) == deref_t and type(expr.op) == address_t:
    return expr.op.op.pluck()

  return

@simplifier
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
    return expr.__class__(expr.op1.op1.pluck(), _value)

  return

@simplifier
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

  !(a - b) becomes a == b
  !(a + b) becomes a == -b

  a - b < 0 becomes a < b
  a - b > 0 becomes a > b
  """

  # !(a && b) becomes !a || !b
  if type(expr) == b_not_t and type(expr.op) == b_and_t:
    return b_or_t(b_not_t(expr.op.op1.pluck()), b_not_t(expr.op.op2.pluck()))

  # !(a || b) becomes !a && !b
  if type(expr) == b_not_t and type(expr.op) == b_or_t:
    return b_and_t(b_not_t(expr.op.op1.pluck()), b_not_t(expr.op.op2.pluck()))

  # !(a == b) becomes a != b
  if type(expr) == b_not_t and type(expr.op) == eq_t:
    return neq_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a != b) becomes a == b
  if type(expr) == b_not_t and type(expr.op) == neq_t:
    return eq_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(!(expr)) becomes expr
  if type(expr) == b_not_t and type(expr.op) == b_not_t:
    return expr.op.op.pluck()

  # a == 0 becomes !a
  if type(expr) == eq_t and type(expr.op2) == value_t and expr.op2.value == 0:
    return b_not_t(expr.op1.pluck())

  # !(a < b) becomes a >= b
  if type(expr) == b_not_t and type(expr.op) == lower_t:
    return aeq_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a > b) becomes a <= b
  if type(expr) == b_not_t and type(expr.op) == above_t:
    return leq_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a >= b) becomes a < b
  if type(expr) == b_not_t and type(expr.op) == aeq_t:
    return lower_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a <= b) becomes a > b
  if type(expr) == b_not_t and type(expr.op) == leq_t:
    return above_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a - b) becomes a == b
  if type(expr) == b_not_t and type(expr.op) == sub_t:
    return eq_t(expr.op.op1.pluck(), expr.op.op2.pluck())

  # !(a + b) becomes a == -b
  if type(expr) == b_not_t and type(expr.op) == add_t:
    return eq_t(expr.op.op1.pluck(), neg_t(expr.op.op2.pluck()))

  #  a - b < 0 becomes a < b
  #  a - b > 0 becomes a > b
  if type(expr) in (lower_t, above_t) and type(expr.op1) == sub_t:
    return lower_t(expr.op1.op1.pluck(), expr.op1.op2.pluck())

  return

@simplifier
def equalities(expr):
  """ equalities """

  # a == b || a > b becomes a >= b
  # a == b || a < b becomes a <= b
  if type(expr) == b_or_t and \
      type(expr.op1) == eq_t and type(expr.op2) in (lower_t, above_t) and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    cls =  {lower_t: leq_t, above_t: aeq_t}[type(expr.op2)]
    return cls(expr.op1.op1.pluck(), expr.op1.op2.pluck())

  # a > b || a == b becomes a >= b
  # a < b || a == b becomes a <= b
  if type(expr) == b_or_t and \
      type(expr.op1) in (lower_t, above_t) and type(expr.op2) == eq_t and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    cls =  {lower_t: leq_t, above_t: aeq_t}[type(expr.op1)]
    return cls(expr.op1.op1.pluck(), expr.op1.op2.pluck())

  # a == b || a <= b becomes a <= b
  # a == b || a >= b becomes a >= b
  if type(expr) == b_or_t and \
      type(expr.op1) == eq_t and type(expr.op2) in (leq_t, aeq_t) and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    return expr.op2.pluck()

  # a <= b || a == b becomes a <= b
  # a >= b || a == b becomes a >= b
  if type(expr) == b_or_t and \
      type(expr.op1) in (leq_t, aeq_t) and type(expr.op2) == eq_t and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    return expr.op1.pluck()

  # a != b && a >= b becomes a > b
  # a != b && a <= b becomes a < b
  # a != b && a > b becomes a > b
  # a != b && a < b becomes a < b
  if type(expr) == b_and_t and \
      type(expr.op1) == neq_t and type(expr.op2) in (leq_t, aeq_t, above_t, lower_t) and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    cls =  {leq_t: lower_t, aeq_t: above_t, above_t: above_t, lower_t: lower_t}[type(expr.op2)]
    return cls(expr.op1.op1.pluck(), expr.op1.op2.pluck())

  # a >= b && a != b becomes a > b
  # a <= b && a != b becomes a < b
  # a > b && a != b becomes a > b
  # a < b && a != b becomes a < b
  if type(expr) == b_and_t and \
      type(expr.op1) in (leq_t, aeq_t, above_t, lower_t) and type(expr.op2) == neq_t and \
      expr.op1.op1 == expr.op2.op1 and expr.op1.op2 == expr.op2.op2:
    cls =  {leq_t: lower_t, aeq_t: above_t, above_t: above_t, lower_t: lower_t}[type(expr.op1)]
    return cls(expr.op1.op1.pluck(), expr.op1.op2.pluck())

  return

@simplifier
def correct_signs(expr):
  """ substitute addition or substraction by its inverse depending on the operand sign

  x + -y becomes x - y
  x - -y becomes x + y
  """

  if type(expr) == add_t and type(expr.op2) == value_t and expr.op2.value < 0:
    return sub_t(expr.op1.pluck(), value_t(abs(expr.op2.value), expr.op2.size))

  if type(expr) == sub_t and type(expr.op2) == value_t and expr.op2.value < 0:
    return add_t(expr.op1.pluck(), value_t(abs(expr.op2.value), expr.op2.size))

  return

@simplifier
def special_xor(expr):
  """ transform xor_t into a literal 0 if both operands to the xor are the same

  x ^ x becomes 0
  """

  if type(expr) == xor_t and expr.op1 == expr.op2:
    return value_t(0, expr.op1.size)

  return

@simplifier
def special_and(expr):
  """ transform the and (&) operator into a simpler form in the special case
  that both operands are the same

  x & x becomes x
  """

  if type(expr) == and_t and expr.op1 == expr.op2:
    return expr.op1.pluck()

  return

def once(expr, deep=False):
  """ run all filters and return the first available simplification """

  for filter in __all__:
    newexpr = filter(expr)
    if newexpr:
      if expr.parent:
        for op in expr.iteroperands():
          if isinstance(op, assignable_t):
            op.unlink()
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
