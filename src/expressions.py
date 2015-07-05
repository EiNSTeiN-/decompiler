
class uses_list(list):

  def copy(self):
    return uses_list(self[:])

  def remove(self, item):
    for idx in range(len(self)):
      if self[idx] is item:
        self.pop(idx)
        return
    raise IndexError('remove(x): x not found in list')

  def append(self, item):
    for idx in range(len(self)):
      if self[idx] is item:
        raise IndexError('append(x): x already in list')
    return list.append(self, item)

class assignable_t(object):
  """ any object that can be assigned.

  They include: regloc_t, var_t, arg_t, deref_t.
  """

  def __init__(self, index):
    self.index = index
    self.is_def = False
    self.is_uninitialized = False

    self.__definition = None
    self.__uses = uses_list()
    return

  @property
  def definition(self):
    return self.__definition

  @definition.setter
  def definition(self, defn):
    assert isinstance(defn, assignable_t) or defn is None, 'definition must be assignable'
    if self.__definition is not None:
      if defn is None:
        self.__definition.__uses.remove(self)
        self.__definition = None
      else:
        raise RuntimeError('definition: already set')
    else:
      self.__definition = defn
      if self.__definition is not None:
        self.__definition.__uses.append(self)
    return

  @property
  def uses(self):
    """ get a immutable copy of the uses list. """
    return tuple(self.__uses)

  def clean(self, **kwargs):
    """ returns a copy of this object without index. """
    cp = self.copy(**kwargs)
    for op in cp.iteroperands():
      op.index = None
    return cp

  def unlink(self):
    for op in self.iteroperands():
      if isinstance(op, assignable_t):
        if op.definition:
          op.definition = None
        for use in op.uses:
          use.definition = None
    return self

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

  def is_parent(self, wanted):
    """ Check if 'obj' is a parent of 'self'. """
    import statements
    obj = self
    while obj:
      if not obj.__parent:
        break
      if isinstance(obj.__parent[0], statements.statement_t):
        break
      if obj.__parent[0] is wanted:
        return True
      obj = obj.__parent[0]

    return False

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
    assert new.parent
    old.parent = None # unlink the old parent to maintain consistency.
    return old

  def pluck(self):
    """ remove the current expression from its current place in the tree """
    k = self.__parent[1]
    self.__parent[0][k] = None
    self.__parent = None
    return self

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

  def copy(self, with_definition=False):
    copy = self.__class__(self.which, size=self.size, name=self.name, index=self.index)
    if with_definition:
      copy.definition = self.definition
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

  def iteroperands(self, depth_first=False, ltr=True):
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

    assert type(value) in (int, long), "expected int, not %s" % (type(value), )
    self.value = value
    self.size = size
    return

  def copy(self, **kwargs):
    return value_t(self.value, self.size)

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.value == other.value

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.value, ))

  def __repr__(self):
    return '<value %u>' % self.value

  def iteroperands(self, depth_first=False, ltr=True):
    yield self
    return

  def unlink(self):
    pass

class var_t(assignable_t, replaceable_t):
  """ a local variable to a function """

  def __init__(self, where, name=None, index=None):
    """  A local variable.

    `where`: the location where the value of this variable is stored.
    `name`: the variable name
    """

    assignable_t.__init__(self, index)
    replaceable_t.__init__(self)

    self.where = where
    #~ self.size = size
    self.name = name or str(self.where)
    return

  def copy(self, with_definition=False):
    copy = self.__class__(self.where, name=self.name, index=self.index)
    if with_definition:
      copy.definition = self.definition
    return copy

  def no_index_eq(self, other):
    return isinstance(other, self.__class__) and self.where == other.where

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.where == other.where and \
      self.index == other.index

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.where, ))

  def __repr__(self):
    name = self.name
    if self.index is not None:
      name += '@%u' % self.index
    return '<var %s>' % (name, )

  def iteroperands(self, depth_first=False, ltr=True):
    yield self
    return

class stack_var_t(var_t):
  def __repr__(self):
    name = self.name
    if self.index is not None:
      name += '@%u' % self.index
    return '<stack-var %s>' % (name, )


class arg_t(assignable_t, replaceable_t):
  """ a function argument """

  def __init__(self, where, name=None, index=None):
    """  A local argument.

    `where`: the location where the value of this argument is stored.
    `name`: the argument name
    """

    assignable_t.__init__(self, index)
    replaceable_t.__init__(self)

    self.where = where
    #~ self.size = size
    self.name = name or str(self.where)

    return

  def copy(self, with_definition=False):
    copy = arg_t(self.where.copy() if self.where else None, name=self.name, index=self.index)
    if with_definition:
      copy.definition = self.definition
    return copy

  def no_index_eq(self, other):
    return isinstance(other, self.__class__) and self.where == other.where

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.where == other.where and \
      self.index == other.index

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.where, ))

  def __repr__(self):
    name = self.name
    if self.index is not None:
      name += '@%u' % self.index
    return '<arg %s>' % (name, )

  def iteroperands(self, depth_first=False, ltr=True):
    yield self
    return

class expr_t(replaceable_t):

  def __init__(self, *operands, **kwargs):

    replaceable_t.__init__(self)

    self.__size = kwargs.pop('size', None)
    assert len(kwargs) == 0, "unrecognized constructor option: %s" % (repr(kwargs.keys()), )

    self.__operands = [None for i in operands]
    for i in range(len(operands)):
        self[i] = operands[i]

    return

  @property
  def size(self):
    return self.__size

  def __getitem__(self, key):
    return self.__operands[key]

  def __setitem__(self, key, value):
    if value is not None:
      assert isinstance(value, replaceable_t), 'operand %s is not replaceable' % (repr(value), )
      assert value.parent is None, 'operand %s already has a parent? tried to assign into #%s of %s' % (value.__class__.__name__, str(key), self.__class__.__name__)
      value.parent = (self, key)
    self.__operands[key] = value
    return

  def remove(self, op):
    self.__operands.remove(op)
    for i in range(len(self.__operands)):
      _op = self.__operands[i]
      _op.parent = (self, i)
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

  def iteroperands(self, depth_first=False, ltr=True):
    """ iterate over all operands, depth first, left to right """

    if not depth_first:
      yield self
    ops = self.__operands if ltr else reversed(self.__operands)
    for o in ops:
      if not o:
        continue
      for _o in o.iteroperands(depth_first, ltr):
        yield _o
    if depth_first:
      yield self
    return

  def unlink(self):
    if isinstance(self, assignable_t):
      assignable_t.unlink(self)
    else:
      for op in self.iteroperands():
        if isinstance(op, assignable_t):
          op.unlink()
    return

class params_t(expr_t):
  """ call parameters """

  def __init__(self, *operands):
    expr_t.__init__(self, *operands)
    return

  def __repr__(self):
    return '<params %s>' % ([repr(op) for op in self.operands])

  def copy(self, **kwargs):
    return self.__class__(*[op.copy(**kwargs) for op in self.operands])

class call_t(expr_t):
  def __init__(self, fct, stack, params):
    expr_t.__init__(self, fct, stack, params)
    return

  @property
  def fct(self): return self[0]

  @fct.setter
  def fct(self, value): self[0] = value

  @property
  def stack(self): return self[1]

  @stack.setter
  def stack(self, value): self[1] = value

  @property
  def params(self): return self[2]

  @params.setter
  def params(self, value): self[2] = value

  def __repr__(self):
    return '<call %s %s %s>' % (repr(self.fct), repr(self.stack), repr(self.params))

  def copy(self, **kwargs):
    return self.__class__(
      self.fct.copy(**kwargs),
      self.stack.copy(**kwargs) if self.stack else  None,
      self.params.copy(**kwargs),
    )

class phi_t(expr_t):
  def __init__(self, *operands):
    expr_t.__init__(self, *operands)
    return

  def __repr__(self):
    return '<phi %s>' % ([repr(op) for op in self.operands])

  def copy(self, **kwargs):
    return self.__class__(*[op.copy(**kwargs) for op in self.operands])

  def __setitem__(self, key, value):
    if value is not None:
      assert type(value) in (deref_t, regloc_t, arg_t, stack_var_t, var_t), 'phi does not accept operand %s of type %s' % (repr(value), type(value))
    return expr_t.__setitem__(self, key, value)


# #####
# Unary expressions (two operands)
# #####

class uexpr_t(expr_t):
  """ base class for unary expressions """

  def __init__(self, operator, op, **kwargs):
    self.operator = operator
    expr_t.__init__(self, op, **kwargs)
    return

  def copy(self, **kwargs):
    return self.__class__(self.op.copy(**kwargs))

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

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '~', op, **kwargs)
    return

class b_not_t(uexpr_t):
  """ boolean negation of operand. """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '!', op, **kwargs)
    return

class deref_t(uexpr_t, assignable_t):
  """ indicate dereferencing of a pointer to a memory location. """

  def __init__(self, op, size=None, index=None, **kwargs):
    assignable_t.__init__(self, index)
    uexpr_t.__init__(self, '*', op, size=size, **kwargs)
    return

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.operator == other.operator \
        and self.op == other.op and self.index == other.index

  def __ne__(self, other):
    return not self.__eq__(other)

  def __hash__(self):
    return hash((self.operator, self.op, self.index))

  def copy(self, with_definition=False):
    copy = self.__class__(self.op.copy(with_definition=with_definition), self.size, self.index)
    if with_definition:
      copy.definition = self.definition
    return copy

  def no_index_eq(self, other):
    return isinstance(other, uexpr_t) and self.operator == other.operator \
      and self.op == other.op

class address_t(uexpr_t):
  """ indicate the address of the given expression (& unary operator). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '&', op, **kwargs)
    return

class neg_t(uexpr_t):
  """ equivalent to -(op). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '-', op, **kwargs)
    return

class preinc_t(uexpr_t):
  """ pre-increment (++i). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '++', op, **kwargs)
    return

class predec_t(uexpr_t):
  """ pre-decrement (--i). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '--', op, **kwargs)
    return

class postinc_t(uexpr_t):
  """ post-increment (i++). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '++', op, **kwargs)
    return

class postdec_t(uexpr_t):
  """ post-decrement (i--). """

  def __init__(self, op, **kwargs):
    uexpr_t.__init__(self, '--', op, **kwargs)
    return


# #####
# Binary expressions (two operands)
# #####

class bexpr_t(expr_t):
  """ "normal" binary expression. """

  def __init__(self, op1, operator, op2, **kwargs):
    self.operator = operator
    expr_t.__init__(self, op1, op2, **kwargs)
    return

  def copy(self, **kwargs):
    return self.__class__(self.op1.copy(**kwargs), self.op2.copy(**kwargs))

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

class assign_t(bexpr_t):
  """ represent the initialization of a location to a particular expression. """

  def __init__(self, op1, op2, **kwargs):
    """ op1: the location being initialized. op2: the expression it is initialized to. """
    assert isinstance(op1, assignable_t), 'left side of assign_t is not assignable'
    bexpr_t.__init__(self, op1, '=', op2, **kwargs)
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

  @property
  def size(self):
    return max(self.op1.size, self.op2.size)

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
