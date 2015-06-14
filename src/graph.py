""" Holds the basic block representation prior to and during disassembly. """

from expressions import *
from statements import *

import filters.simplify_expressions

class node_t(object):

  def __init__(self, ea):

    self.ea = ea

    self.items = []
    self.statements = []

    self.jump_from = []
    self.jump_to = []

    self.falls_into = None
    self.is_return_node = False

    return

  def add_jump_from(self, node):
    if node not in self.jump_from:
      self.jump_from.append(node)
    return

  def add_jump_to(self, node):
    if node not in self.jump_to:
      self.jump_to.append(node)
    return

  def __repr__(self):
    return '<node_t %08x %s>' % (self.ea, repr(self.statements), )

class graph_t(object):

  def __init__(self, ea, arch, follow_calls=True):

    self.ea = ea
    self.follow_calls = follow_calls
    self.arch = arch

    self.func_items = self.arch.get_function_items(self.ea)

    self.nodes = {}

    return

  def __repr__(self):

    lines = []

    for node in self.nodes.values():
      lines.append('<loc_%x>' % (node.ea, ))
      for stmt in node.statements:
        lines += repr(stmt)
      lines.append('')

    return '\n'.join(lines)

  def jump_targets(self):
    """ find each point in the function which is the
    destination of a jump (conditional or not).

    jump destinations are the points that delimit new
    blocks. """

    for item in self.func_items:
      if self.arch.has_jump(item):
        for dest in self.arch.jump_branches(item):
          if type(dest) == value_t and dest.value in self.func_items:
            ea = dest.value
            yield ea
    return

  @property
  def entry_node(self):
    return self.nodes[self.ea]

  def find_control_flow(self):

    # find all jump targets
    jump_targets = list(set(self.jump_targets()))

    # prepare first node
    node = node_t(self.ea)
    next_nodes = [node, ]
    self.nodes[self.ea] = node

    # create all empty nodes.
    for target in jump_targets:
      if target in self.nodes.keys():
        continue
      node = node_t(target)
      self.nodes[target] = node
      next_nodes.append(node)

    while len(next_nodes) > 0:

      # get next node
      node = next_nodes.pop(0)
      ea = node.ea

      while True:
        # append current ea to the node's locations array
        node.items.append(ea)

        if self.arch.is_return(ea):
          node.is_return_node = True
          break

        elif self.arch.has_jump(ea):
          for dest in self.arch.jump_branches(ea):
            if type(dest) != value_t:
              print '%x: cannot follow jump to %s' % (ea, repr(dest))
              continue

            ea_to = dest.value
            if ea_to not in self.func_items:
              print '%x: jumped outside of function to %x' % (ea, ea_to, )
            else:
              tonode = self.nodes[ea_to]
              node.add_jump_to(tonode)
              tonode.add_jump_from(node)
          break

        next_ea = self.arch.next_instruction_ea(ea)

        if next_ea not in self.func_items:
          print '%x: jumped outside of function: %x' % (ea, next_ea)
          break

        ea = next_ea

        # the next instruction is part of another node...
        if ea in jump_targets:
          tonode = self.nodes[ea]
          node.add_jump_to(tonode)
          tonode.add_jump_from(node)

          node.falls_into = tonode
          break

    return

  def iternodes(self):
    """ iterate over all nodes in the order that they most logically follow each other. """

    done = []
    nodes = [self.entry_node, ]

    while len(nodes) > 0:

      node = nodes.pop(0)

      if node in done:
        continue

      done.append(node)

      yield node

      for node in node.jump_to:
        if node not in done:
          if node in nodes:
            # re-add at the end
            nodes.remove(node)
          nodes.append(node)

    return

  def simplify_expressions(self, expr):
    """ combine expressions until they cannot be combined any more. return the new expression. """
    return filters.simplify_expressions.run(expr, deep=True)

  def simplify_statement(self, stmt):
    """ find any expression present in a statement and simplify them. if the statement
        has other statements nested (as is the case for if-then, while, etc), then
        sub-statements are also processed. """

    # simplify sub-statements
    for _stmt in stmt.statements:
      self.simplify_statement(_stmt)

    filters.simplify_expressions.run(stmt.expr, deep=True)

    return stmt

  def make_statement(self, ea, item):
    """ always return a statement from an expression or a statement. """

    if isinstance(item, statement_t):
      stmt = item
    elif isinstance(item, expr_t):
      stmt = statement_t(ea, item)
    else:
      raise RuntimeError("don't know how to make a statement with %s" % (repr(item), ))

    return stmt

  def transform_ir(self):
    """ transform the program into the intermediate representation. """

    for node in self.iternodes():

      # for all item in the node, process each statement.
      for item in node.items:
        for expr in self.arch.generate_statements(item):

          # upgrade expr to statement if necessary
          stmt = self.make_statement(item, expr)

          # apply simplification rules to all expressions in this statement
          stmt = self.simplify_statement(stmt)

          node.statements.append(stmt)

      # if the node 'falls' without branch instruction into another one, add a goto for clarity
      if node.falls_into:
        node.statements.append(goto_t(item, value_t(node.falls_into.ea, self.arch.address_size)))

    return

