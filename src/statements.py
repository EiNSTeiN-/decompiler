
from expressions import *

class statement_t(object):
  """ defines a statement containing an expression. """

  def __init__(self, ea, expr):
    self.ea = ea
    self.expr = expr
    self.container = None
    return

  def copy(self):
    return self.__class__(self.ea, self.expr.copy() if self.expr else None)

  def index(self):
    """ return the statement index inside its parent
        container, or None if container is None """
    if self.container is None:
        return
    return self.container.index(self)

  def remove(self):
    """ removes the statement from its container. return True if
        container is not None and the removal succeeded. """
    if self.container is None:
        return
    return self.container.remove(self)

  @property
  def expr(self):
    return self.__expr

  @expr.setter
  def expr(self, value):
    if value is not None:
      assert isinstance(value, replaceable_t), 'expr is not replaceable'
      value.parent = (self, 'expr')
    self.__expr = value
    return

  def __getitem__(self, key):
    assert key in ('expr', ), "%s is not a valid key" % (key, )
    if key == 'expr':
      return self.expr
    else:
      raise IndexError('key not supported')
    return

  def __setitem__(self, key, value):
    assert key in ('expr', )
    if key == 'expr':
      self.expr = value
    else:
      raise IndexError('key not supported')
    return

  def __hash__(self):
    return hash((self.__class__, self.expr))

  def __repr__(self):
    return '<%s statement %s>' % (hex(self.ea) if self.ea else '~',
      repr(self.expr), )

  @property
  def expressions(self):
    """ by default, statements contain only one expression. some statements may contain
        no expressions (break, continue) and others may contain many (for loops, ...). """
    yield self.expr
    return

  @property
  def statements(self):
    """ by default, no statements are present in this one. """
    return []

  @property
  def containers(self):
    """ by default, no containers are present in this one. """
    return []

class container_t(object):
  """ a container contains statements. """

  def __init__(self, block, __list=None):
    assert type(block).__name__ == 'function_block_t', 'block must be function_block_t, not %s' % (type(block), )
    self.__block = block
    self.__list = __list or []
    for item in self.__list:
      item.container = self
    return

  def __repr__(self):
    return repr(self.__list)

  def __len__(self):
    return len(self.__list)

  def __getitem__(self, key):
    return self.__list[key]

  def __setitem__(self, key, value):
    if type(key) == slice:
      for item in value:
        assert isinstance(item, statement_t), 'cannot set non-statement to container'
        item.container = self
    else:
      assert isinstance(value, statement_t), 'cannot set non-statement to container'
      value.container = self
    self.__list.__setitem__(key, value)
    return

  def __hash__(self):
    return hash(tuple(self.statements))

  def copy(self):
    copy = container_t(self.block, [stmt.copy() for stmt in self])
    return copy

  def iteritems(self):
    for i in range(len(self.__list)):
      yield i, self.__list[i]
    return

  @property
  def block(self):
    return self.__block

  @property
  def statements(self):
    for item in self.__list:
      yield item
    return

  def add(self, stmt):
    assert isinstance(stmt, statement_t), 'cannot add non-statement: %s' % (repr(stmt), )
    self.__list.append(stmt)
    stmt.container = self
    return

  def extend(self, _new):
    for stmt in _new:
      assert isinstance(stmt, statement_t), 'cannot add non-statement to container'
      stmt.container = self
      self.__list.append(stmt)
    return

  def insert(self, key, _new):
    assert isinstance(_new, statement_t), 'cannot add non-statement: %s' % (repr(_new), )
    self.__list.insert(key, _new)
    _new.container = self
    return

  def pop(self, key=-1):
    stmt = self.__list.pop(key)
    if stmt:
      stmt.container = None
    return stmt

  def index(self, stmt):
    return self.__list.index(stmt)

  def __iter__(self):
    for item in self.__list:
      yield item
    return

  def remove(self, stmt):
    if stmt in self.__list:
      stmt.container = None
    return self.__list.remove(stmt)

class if_t(statement_t):
  """ if_t is a statement containing an expression and a then-side,
      and optionally an else-side. """

  def __init__(self, ea, expr, then, _else=None):
    statement_t.__init__(self, ea, expr)
    assert isinstance(then, container_t), 'then-side must be container_t'
    assert _else is None or isinstance(_else, container_t), 'else-side must be container_t'
    self.then_expr = then
    self.else_expr = _else
    return

  def __repr__(self):
    return '<%s if %s then %s else %s>' % (hex(self.ea) if self.ea else '~',
      repr(self.expr), repr(self.then_expr), repr(self.else_expr))

  def __hash__(self):
    return hash((self.__class__, self.expr, self.then_expr, self.else_expr))

  def copy(self):
    return self.__class__(self.ea, self.expr.copy(), self.then_expr.copy(), self.else_expr.copy() if self.else_expr else None)

  @property
  def statements(self):
    for stmt in self.then_expr.statements:
      yield stmt
    if self.else_expr:
      for stmt in self.else_expr.statements:
        yield stmt
    return

  @property
  def containers(self):
    yield self.then_expr
    if self.else_expr:
      yield self.else_expr
    return

class while_t(statement_t):
  """ a while_t statement of the type 'while(expr) { ... }'. """

  def __init__(self, ea, expr, loop_container):
    statement_t.__init__(self, ea, expr)
    assert isinstance(loop_container, container_t), '2nd argument to while_t must be container_t'
    self.loop_container = loop_container
    return

  def __repr__(self):
    return '<%s while %s do %s>' % (hex(self.ea) if self.ea else '~',
      repr(self.expr), repr(self.loop_container))

  def __hash__(self):
    return hash((self.__class__, self.expr, self.loop_container))

  def copy(self):
    return self.__class__(self.ea, self.expr.copy(), self.loop_container.copy())

  @property
  def statements(self):
    for stmt in self.loop_container:
      yield stmt
    return

  @property
  def containers(self):
    yield self.loop_container
    return

class do_while_t(statement_t):
  """ a do_while_t statement of the type 'do { ... } while(expr)'. """

  def __init__(self, ea, expr, loop_container):
    statement_t.__init__(self, ea, expr)
    assert isinstance(loop_container, container_t), '2nd argument to while_t must be container_t'
    self.loop_container = loop_container
    return

  def __repr__(self):
    return '<%s do %s while %s>' % (hex(self.ea) if self.ea else '~',
      repr(self.loop_container), repr(self.expr), )

  def __hash__(self):
    return hash((self.__class__, self.expr, self.loop_container))

  def copy(self):
    return self.__class__(self.ea, self.expr.copy(), self.loop_container.copy())

  @property
  def statements(self):
    for stmt in self.loop_container:
      yield stmt
    return

  @property
  def containers(self):
    yield self.loop_container
    return

class goto_t(statement_t):

  def __init__(self, ea, dst):
    statement_t.__init__(self, ea, dst)
    return

  def __eq__(self, other):
    return isinstance(other, self.__class__) and self.expr == other.expr

  def __repr__(self):
    s = hex(self.expr.value) if type(self.expr) == value_t else str(self.expr)
    return '<%s goto %s>' % (hex(self.ea) if self.ea else '~', s, )

  def is_known(self):
    return type(self.expr) == value_t

class branch_t(statement_t):

  def __init__(self, ea, expr, true, false):
    statement_t.__init__(self, ea, expr)
    self.true = true
    self.false = false
    return

  def __eq__(self, other):
    return type(other) == branch_t and self.expr == other.expr and \
            self.true == other.true and self.false == other.false

  def __repr__(self):
    return '<%s branch %s true:%s false:%s>' % (hex(self.ea) if self.ea else '~',
      repr(self.expr), repr(self.true), repr(self.false))

  def __hash__(self):
    return hash((self.__class__, self.expr, self.true, self.false))

  def copy(self):
    return self.__class__(self.ea, self.expr.copy(), self.true.copy(), self.false.copy())

  @property
  def expressions(self):
    """ by default, statements contain only one expression. some statements may contain
        no expressions (break, continue) and others may contain many (for loops, ...). """
    yield self.expr
    yield self.true
    yield self.false
    return

class return_t(statement_t):
  def __init__(self, ea, expr=None):
    statement_t.__init__(self, ea, expr)
    return

  def __repr__(self):
    return '<%s return %s>' % (hex(self.ea) if self.ea else '~',
      repr(self.expr) if self.expr else 'void', )

  @property
  def expressions(self):
    if self.expr:
      yield self.expr

class break_t(statement_t):
  def __init__(self, ea):
    statement_t.__init__(self, ea, None)
    return

  def __repr__(self):
    return '<%s break>' % (hex(self.ea) if self.ea else '~', )

  @property
  def expressions(self):
    """ no expressions """
    return

class continue_t(statement_t):
  def __init__(self, ea):
    statement_t.__init__(self, ea, None)
    return

  def __repr__(self):
    return '<%s continue>' % (hex(self.ea) if self.ea else '~', )

  @property
  def expressions(self):
    """ no expressions """
    return
