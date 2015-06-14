
class iterator_t(object):
  def __init__(self, function):
    self.function = function
    return

class block_iterator_t(iterator_t):
  def __iter__(self):
    for block in self.function.blocks.values():
      yield block

class container_iterator_t(iterator_t):
  def __iter__(self):
    for block in block_iterator_t(self.function):
      for container in self.iter_container(block.container):
        yield container

  def iter_container(self, container):
    yield container
    for stmt in container:
      for _container in stmt.containers:
        for __container in self.iter_container(_container):
          yield __container
    return

class statement_iterator_t(iterator_t):
  def __iter__(self):
    for container in container_iterator_t(self.function):
      for stmt in list(container.statements):
        yield stmt

class expression_iterator_t(iterator_t):
  def __iter__(self):
    for stmt in statement_iterator_t(self.function):
      for expr in list(stmt.expressions):
        yield expr

class operand_iterator_t(iterator_t):
  def __init__(self, function, depth_first=False, ltr=True, filter=None, klass=None):
    self.depth_first = depth_first
    self.ltr = ltr
    if filter:
      self.filter = filter
    elif klass:
      self.filter = lambda op: isinstance(op, klass)
    else:
      self.filter = None
    iterator_t.__init__(self, function)
    return

  def __iter__(self):
    for expr in expression_iterator_t(self.function):
      for op in expr.iteroperands(self.depth_first, self.ltr):
        if self.filter is None or self.filter(op):
          yield op
