""" Calculate and keep track of the definition-use chain.

The du_t object holds a list of all definition location and their
corresponding du_chain_t which holds the location itself and all of
the uses of this location.
"""

from statements import *
from expressions import *

class du_chain_t(object):
  """ a class that points to a single definition and possibly zero or more of its uses. """
  def __init__(self, loc):

    # a reference to the assigned variable.
    self.loc = loc

    # a list containing references to all
    self.uses = []

    return

  def index(self):
    """ the du_chain_t index. returns the index of `self.loc` """
    return self.loc.index

  def get_definition_value(self):
    """ return the right side of the assignment that this def-use chain gets assigned to. """

    assign = self.loc.parent
    if type(assign) == assign_t:
      return assign.op2

    return

class du_t(object):
  """ the object containing all def-use chains. """

  def __init__(self, flow, args):

    # a flow_t object.
    self.flow = flow

    # list of arguments. this is needed to provide a definition location for some of
    # the registers that are used without being defined.
    self.args = args

    # dictionary of `int`: `du_chain_t`. the index is the same index as the location
    # that each du_chain_t represent.
    self.map = {}

    return

  def get_def(self, expr):
    return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and not isinstance(defreg, deref_t) and defreg.is_def]

  def get_uses(self, expr):
    return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and not isinstance(defreg, deref_t) and not defreg.is_def]

  def do_expression(self, expr):

    d = self.get_def(expr)
    u = self.get_uses(expr)

    assert len(d) <= 1, 'should not have more than one definition per statement'

    for loc in d:
      assert loc.index is not None, 'expression needs an index'
      if loc.index in self.map:
        chain = self.map[loc.index]
        assert chain.loc is None, 'location %s is defined multiple times' % (repr(loc), )
        chain.loc = loc
      else:
        self.map[loc.index] = du_chain_t(loc)

    for loc in u:
      assert loc.index is not None, 'expression needs an index'
      #~ assert , 'location %s should have a definition before its use' % (repr(loc), )
      if loc.index not in self.map:
        # this location is assigned prior to being defined
        # (could be either a global variable, or uninitialized stack location which is not an argument...)
        self.map[loc.index] = du_chain_t(None)
      self.map[loc.index].uses.append(loc)

    return

  def do_container(self, parent):
    for stmt in parent.statements:
      self.do_container(stmt)
      for expr in stmt.expressions:
        self.do_expression(expr)
    return

  def populate(self):

    for arg in self.args:
      assert arg.index is not None, 'expression needs an index'
      assert arg.index not in self.map, 'definition is defined multiple times'
      self.map[arg.index] = du_chain_t(arg)

    for ea, block in self.flow.blocks.items():
      self.do_container(block.container)

    return

  def remove(self, stmt):
    """ Remove all assignable_t expressions that are contained in `stmt` from
        any chain that we have. This method can be called just before removing
        any statement in order to keep the state consistent """

    for expr in stmt.expressions:
      for op in expr.iteroperands():
        if isinstance(op, assignable_t):
          chain = self.map[op.index]
          if op is chain.loc:
            assert len(chain.uses) == 0, 'cannot remove statement if its defined location still has uses'
            del self.map[op.index]
            continue
          chain.uses.remove(op)

    return

  def find_chain(self, loc):

    if not isinstance(loc, assignable_t):
      return

    if loc.index is None:
      return

    if loc.index not in self.map:
      return

    return self.map[loc.index]
