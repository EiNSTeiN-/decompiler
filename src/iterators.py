
class iterator_t(object):
  def __init__(self, flow):
    self.flow = flow
    return

class block_iterator_t(iterator_t):
  def __iter__(self):
    for block in self.flow.iterblocks():
      yield block

class container_iterator_t(iterator_t):
  def __iter__(self):
    for block in block_iterator_t(self.flow):
      yield block.container

class statement_iterator_t(iterator_t):
  def __iter__(self):
    for container in container_iterator_t(self.flow):
      for stmt in list(container.statements):
        yield stmt

class expression_iterator_t(iterator_t):
  def __iter__(self):
    for stmt in statement_iterator_t(self.flow):
      for expr in list(stmt.expressions):
        yield expr

class operand_iterator_t(iterator_t):
  def __init__(self, flow, depth_first=False, ltr=True):
    self.depth_first = depth_first
    self.ltr = ltr
    iterator_t.__init__(self, flow)
    return

  def __iter__(self):
    for expr in expression_iterator_t(self.flow):
      for op in expr.iteroperands(self.depth_first, self.ltr):
        yield op
