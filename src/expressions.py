
class assignable_t(object):
  """ any object that can be assigned.

  They include: regloc_t, var_t, arg_t, deref_t.
  """

  def __init__(self, index):
    self.index = index
    self.is_def = False

    self.definition = None
    self.uses = []
    return

  def clean(self):
    """ returns a copy of this object without index. """
    cp = self.copy()
    for op in cp.iteroperands():
      op.index = None
      op.definition = None
      op.uses = []
    return cp

class replaceable_t(object):
  """ abstracts the logic behind tracking an object's parent so the object
      can be replaced without knowing in advance what its parent is, with
      a reference to only the object itself.

      an example of replacing an operand:

          loc = regloc_t(0) # eax
          e = add_t(value(1), loc) # e contains '1 + eax'
          loc.replace(value(8)) # now e contains '1 + 8'

      this doesn't work when comes the time to 'wrap' an operand into another,
      because checks are made to ensure an operand is added to _only_ one
      parent expression at a time. the operand can be copied, however:

          loc = regloc_t(0) # eax
          e = add_t(value(1), loc) # e contains '1 + eax'
          # the following line wouldn't work:
          loc.replace(deref_t(loc))
          # but this one would:
          loc.replace(deref_t(loc.copy()))

      """

  def __init__(self):
    self.__parent = None
    return

  @property
  def parent_statement(self):
    """ get the nearest parent statement of this expression. """
    import statements
    obj = self
    while obj:
      if not obj.__parent:
        break
      if isinstance(obj.__parent[0], statements.statement_t):
        return obj.__parent[0]
      obj = obj.__parent[0]

    return

  @property
  def parent(self):
    if self.__parent:
      return self.__parent[0]
    return

  @parent.setter
  def parent(self, parent):
    assert type(parent) in (tuple, type(None))
    self.__parent = parent
    return

  def replace(self, new):
    """ replace this object in the parent's operands list for a new object
        and return the old object (which is a reference to 'self'). """
    assert isinstance(new, replaceable_t), 'new object is not replaceable'
    assert self.__parent is not None, 'cannot replace when parent is None in %s by %s' % (repr(self), repr(new))
    k = self.__parent[1]
    old = self.__parent[0][k]
    assert old is self, "parent operand should have been this object ?!"
    self.__parent[0][k] = new
    new.parent = (self.__parent[0], k)
    old.parent = None # unlink the old parent to maintain consistency.
    return old

class regloc_t(assignable_t, replaceable_t):

  def __init__(self, which, size, name=None, index=None):
    """  Register location

    `which`: index of the register
    `size`: size in bits (8, 16, 32, etc...)
    `name`: name of the register (a string that doesn't mean anything except for display)
    `index`: index of the register, assigned after tagging.
    """

    assignable_t.__init__(self, index)
    replaceable_t.__init__(self)

    self.which = which
    self.size = size
    self.name = name

    return

  def copy(self):
    copy = self.__class__(self.which, size=self.size, name=self.name, index=self.index)
    copy.definition = self.definition
    copy.uses = self.uses
    return copy

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.which == other.which and \
            self.index == other.index

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.which, self.index))

  def no_index_eq(self, other):
    return type(other) == type(self) and self.which == other.which

  def __repr__(self):
    if self.name:
      name = self.name
    else:
      name = '#%u' % (self.which, )

    if self.index is not None:
      name += '@%u' % self.index

    return '<reg %s>' % (name, )

  def iteroperands(self):
    yield self
    return

class flagloc_t(regloc_t):
  """ a special flag, which can be anything, depending on the
      architecture. for example the eflags status bits in intel
      assembly. """
  pass

class value_t(replaceable_t):
  """ any literal value """

  def __init__(self, value, size):
    """ A literal value

    `value`: a literal value
    `size`: size in bits (8, 16, 32, etc...)
    """

    replaceable_t.__init__(self)

    self.value = value
    self.size = size
    return

  def copy(self):
    return value_t(self.value, self.size)

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.value == other.value

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.value, ))

  def __repr__(self):
    return '<value %u>' % self.value

  def iteroperands(self):
    yield self
    return

class var_t(assignable_t, replaceable_t):
  """ a local variable to a function """

  def __init__(self, where, name=None):
    """  A local variable.

    `where`: the location where the value of this variable is stored.
    `name`: the variable name
    """

    assignable_t.__init__(self, None)
    replaceable_t.__init__(self)

    self.where = where
    #~ self.size = size
    self.name = name or str(self.where)
    return

  def copy(self):
    copy = var_t(self.where.copy(), name=self.name)
    copy.definition = self.definition
    copy.uses = self.uses
    return copy

  def __eq__(self, other):
    return (isinstance(other, self.__class__) and self.where == other.where)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.where, ))

  def __repr__(self):
    return '<var %s>' % self.name

  def iteroperands(self):
    yield self
    return

class arg_t(assignable_t, replaceable_t):
  """ a function argument """

  def __init__(self, where, name=None):
    """  A local argument.

    `where`: the location where the value of this argument is stored.
    `name`: the argument name
    """

    assignable_t.__init__(self, None)
    replaceable_t.__init__(self)

    self.where = where
    #~ self.size = size
    self.name = name or str(self.where)

    return

  def copy(self):
    copy = arg_t(self.where.copy(), self.name)
    copy.definition = self.definition
    copy.uses = self.uses
    return copy

  def __eq__(self, other):
    return (isinstance(other, self.__class__) and self.where == other.where)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.where, ))

  def __repr__(self):
    return '<arg %s>' % self.name

  def iteroperands(self):
    yield self
    return

class expr_t(replaceable_t):

  def __init__(self, *operands):

    replaceable_t.__init__(self)

    self.__operands = [None for i in operands]
    for i in range(len(operands)):
        self[i] = operands[i]

    return

  def __getitem__(self, key):
    return self.__operands[key]

  def __setitem__(self, key, value):
    if value is not None:
      assert isinstance(value, replaceable_t), 'operand %s is not replaceable' % (repr(value), )
      assert value.parent is None, 'operand %s already has a parent? tried to assign into #%s of %s' % (value.__class__.__name__, str(key), self.__class__.__name__)
      value.parent = (self, key)
    self.__operands[key] = value
    return

  def append(self, op):
    self.__operands.append(None)
    self[len(self.__operands) - 1] = op # go through setitem.
    return

  def __len__(self):
    return len(self.__operands)

  @property
  def operands(self):
    for op in self.__operands:
      yield op
    return

  def iteroperands(self):
    """ iterate over all operands, depth first, left to right """

    for o in self.__operands:
      if not o:
        continue
      for _o in o.iteroperands():
        yield _o
    yield self
    return

class call_t(expr_t):
  def __init__(self, fct, params):
    expr_t.__init__(self, fct, params)
    return

  @property
  def fct(self): return self[0]

  @fct.setter
  def fct(self, value): self[0] = value

  @property
  def params(self): return self[1]

  @params.setter
  def params(self, value): self[1] = value

  def __repr__(self):
    return '<call %s %s>' % (repr(self.fct), repr(self.params))

  def copy(self):
    return call_t(self.fct.copy(), self.params.copy() if self.params else None)

class theta_t(expr_t):
  def __init__(self, *operands):
    expr_t.__init__(self, *operands)
    return

  def __repr__(self):
    return '<theta %s>' % ([repr(op) for op in self.operands])

  def copy(self):
    return theta_t(list(self.operands))


# #####
# Unary expressions (two operands)
# #####

class uexpr_t(expr_t):
  """ base class for unary expressions """

  def __init__(self, operator, op):
    self.operator = operator
    expr_t.__init__(self, op)
    return

  def copy(self):
    return self.__class__(self.op.copy())

  @property
  def op(self): return self[0]

  @op.setter
  def op(self, value): self[0] = value

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.operator == other.operator \
      and self.op == other.op

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.operator, self.op, ))

  def __repr__(self):
    idx = ''
    if isinstance(self, assignable_t) and self.index is not None:
        idx = ' @%u' % (self.index, )
    return '<%s %s %s%s>' % (self.__class__.__name__, self.operator, repr(self.op), idx)

class not_t(uexpr_t):
  """ bitwise NOT operator. """

  def __init__(self, op):
    uexpr_t.__init__(self, '~', op)
    return

class b_not_t(uexpr_t):
  """ boolean negation of operand. """

  def __init__(self, op):
    uexpr_t.__init__(self, '!', op)
    return

class deref_t(uexpr_t, assignable_t):
  """ indicate dereferencing of a pointer to a memory location. """

  def __init__(self, op, size, index=None):
    assignable_t.__init__(self, index)
    uexpr_t.__init__(self, '*', op)
    self.size = size
    return

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.operator == other.operator \
        and self.op == other.op and self.index == other.index

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.operator, self.op, self.index))

  def copy(self):
    copy = self.__class__(self.op.copy(), self.size, self.index)
    copy.definition = self.definition
    copy.uses = self.uses
    return copy

  def no_index_eq(self, other):
    return isinstance(other, uexpr_t) and self.operator == other.operator \
      and self.op == other.op

class address_t(uexpr_t):
  """ indicate the address of the given expression (& unary operator). """

  def __init__(self, op):
    uexpr_t.__init__(self, '&', op)
    return

class neg_t(uexpr_t):
  """ equivalent to -(op). """

  def __init__(self, op):
    uexpr_t.__init__(self, '-', op)
    return

class preinc_t(uexpr_t):
  """ pre-increment (++i). """

  def __init__(self, op):
    uexpr_t.__init__(self, '++', op)
    return

class predec_t(uexpr_t):
  """ pre-decrement (--i). """

  def __init__(self, op):
    uexpr_t.__init__(self, '--', op)
    return

class postinc_t(uexpr_t):
  """ post-increment (i++). """

  def __init__(self, op):
    uexpr_t.__init__(self, '++', op)
    return

class postdec_t(uexpr_t):
  """ post-decrement (i--). """

  def __init__(self, op):
    uexpr_t.__init__(self, '--', op)
    return


# #####
# Binary expressions (two operands)
# #####

class bexpr_t(expr_t):
  """ "normal" binary expression. """

  def __init__(self, op1, operator, op2):
    self.operator = operator
    expr_t.__init__(self, op1, op2)
    return

  def copy(self):
    return self.__class__(self.op1.copy(), self.op2.copy())

  @property
  def op1(self): return self[0]

  @op1.setter
  def op1(self, value): self[0] = value

  @property
  def op2(self): return self[1]

  @op2.setter
  def op2(self, value): self[1] = value

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.operator == other.operator and \
            self.op1 == other.op1 and self.op2 == other.op2

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.operator, self.op1, self.op2))

  def __repr__(self):
    return '<%s %s %s %s>' % (self.__class__.__name__, repr(self.op1), \
            self.operator, repr(self.op2))

class comma_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, ',', op2)
    return

class assign_t(bexpr_t):
  """ represent the initialization of a location to a particular expression. """

  def __init__(self, op1, op2):
    """ op1: the location being initialized. op2: the value it is initialized to. """
    assert isinstance(op1, assignable_t), 'left side of assign_t is not assignable'
    bexpr_t.__init__(self, op1, '=', op2)
    op1.is_def = True
    return

  def __setitem__(self, key, value):
    if key == 0:
      assert isinstance(value, assignable_t), 'left side of assign_t is not assignable: %s (to %s)' % (str(value), str(self))
      value.is_def = True
    bexpr_t.__setitem__(self, key, value)
    return

class add_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '+', op2)
    return

  def add(self, other):
    if type(other) == value_t:
      self.op2.value += other.value
      return
    raise RuntimeError('cannot add %s' % type(other))

  def sub(self, other):
    if type(other) == value_t:
      self.op2.value -= other.value
      return
    raise RuntimeError('cannot sub %s' % type(other))

class sub_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '-', op2)
    return

  def add(self, other):
    if other.__class__ == value_t:
      self.op2.value -= other.value
      return
    raise RuntimeError('cannot add %s' % type(other))

  def sub(self, other):
    if other.__class__ == value_t:
      self.op2.value += other.value
      return
    raise RuntimeError('cannot sub %s' % type(other))

class mul_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '*', op2)
    return

class div_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '/', op2)
    return

class shl_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '<<', op2)
    return

class shr_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '>>', op2)
    return

class xor_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '^', op2)
    return

class and_t(bexpr_t):
  """ bitwise and (&) operator """

  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '&', op2)
    return

class or_t(bexpr_t):
  """ bitwise or (|) operator """

  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '|', op2)
    return

# #####
# Boolean equality/inequality operators
# #####

class b_and_t(bexpr_t):
  """ boolean and (&&) operator """

  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '&&', op2)
    return

class b_or_t(bexpr_t):
  """ boolean and (||) operator """

  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '||', op2)
    return

class eq_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '==', op2)
    return

class neq_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '!=', op2)
    return

class leq_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '<=', op2)
    return

class aeq_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '>=', op2)
    return

class lower_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '<', op2)
    return

class above_t(bexpr_t):
  def __init__(self, op1, op2):
    bexpr_t.__init__(self, op1, '>', op2)
    return

# #####
# Ternary expressions (three operands)
# #####

class texpr_t(expr_t):
  """ ternary expression. """

  def __init__(self, op1, operator1, op2, operator2, op3):
    self.operator1 = operator1
    self.operator2 = operator2
    expr_t.__init__(self, op1, op2, op3)
    return

  @property
  def op1(self): return self[0]

  @op1.setter
  def op1(self, value): self[0] = value

  @property
  def op2(self): return self[1]

  @op2.setter
  def op2(self, value): self[1] = value

  @property
  def op3(self): return self[2]

  @op3.setter
  def op3(self, value): self[2] = value

  def __eq__(self, other):
    return isinstance(other, self.__class__) and \
            self.operator1 == other.operator1 and self.operator2 == other.operator2 and \
            self.op1 == other.op1 and self.op2 == other.op2 and self.op3 == other.op3

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.operator1, self.operator2, self.op1, self.op2))

  def __repr__(self):
    return '<%s %s %s %s %s %s>' % (self.__class__.__name__, repr(self.op1), \
            self.operator1, repr(self.op2), self.operator2, repr(self.op3))

class ternary_if_t(texpr_t):
  def __init__(self, cond, then, _else):
    texpr_t.__init__(self, cond, '?', then, ':', _else)
    return

# #####
# Special operators that define the value of some of the eflag bits.
# #####

class sign_t(uexpr_t):
  def __init__(self, op):
    uexpr_t.__init__(self, '<sign of>', op)
    return

class overflow_t(uexpr_t):
  def __init__(self, op):
    uexpr_t.__init__(self, '<overflow of>', op)
    return

class parity_t(uexpr_t):
  def __init__(self, op):
    uexpr_t.__init__(self, '<parity>', op)
    return

class adjust_t(uexpr_t):
  def __init__(self, op):
    uexpr_t.__init__(self, '<adjust>', op)
    return

class carry_t(uexpr_t):
  def __init__(self, op):
    uexpr_t.__init__(self, '<carry>', op)
    return

