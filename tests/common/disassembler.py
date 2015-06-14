""" Disassembler for testing purposes.

Fake disassembler which makes use of the text-to-IR parser as input
instead of real binary files. This is useful for testing specific parts
of the decompiler without having to deal with real assembly.

The input text is expressed in IR expressions, and may contain labels
and jumps to those labels. Take for example, the following intel assembly:

cmp eax, 0
jz 123

may be translated to:

if (eax == 0) goto 123;

And 'jmp 123' may be replaced simply by 'goto 123;'.

Labels may be numerical only. Line numbers may be used for ease of
reading.

"""

from ply import ir_parser

from ir.generic import ir_base

from expressions import *
from statements import *

class parser_disassembler(ir_base):

  def __init__(self, text):
    ir_base.__init__(self)

    self.text = text
    self.address_size = 32
    self.stackreg = 'esp'

    try:
      self.tree = ir_parser.parse(self.text)
    except:
      print 'Could not parse IR from text.'
      raise

    return

  def is_stackreg(self, reg):
    """ return True if the register is the stack register """
    return isinstance(reg, regloc_t) and reg.name == self.stackreg

  def is_stackvar(self, expr):
    return ((type(expr) in (sub_t, add_t) and \
            self.is_stackreg(expr.op1) and type(expr.op2) == value_t))

  def __lineno_to_ea(self, lineno):
    """ translate a line number 'lineno' from the input text into an address 'ea'. """
    for _lineno, stmt in self.tree:
      if lineno == _lineno:
        return self.tree.index((_lineno, stmt))
    raise RuntimeError('There is no line with address %u in input text' % (lineno, ))

  def __ea_to_lineno(self, ea):
    """ translate an address 'ea' from the input text into an address 'lineno' in the parsed tree. """
    return self.tree[ea][0]

  def __stmt(self, ea):
    self.tree[ea][1].ea = ea
    return self.tree[ea][1]

  def is_return(self, ea):
    """ return True if this is a return instruction. """
    stmt = self.__stmt(ea)
    return type(stmt) == return_t

  def has_jump(self, ea):
    """ return true if this instruction is a jump """
    stmt = self.__stmt(ea)
    return type(stmt) in (goto_t, ir_parser.conditional_goto_t)

  def next_instruction_ea(self, ea):
    """ return the address of the next instruction. """
    return ea + 1

  def jump_branches(self, ea):
    """ if this instruction is a jump, yield the destination(s)
        of the jump, of which there may be more than one."""

    stmt = self.__stmt(ea)
    if type(stmt) == ir_parser.conditional_goto_t:
      yield value_t(self.__lineno_to_ea(stmt.loc), 32)
      yield value_t(self.next_instruction_ea(ea), 32)
    elif type(stmt) == goto_t:
      yield value_t(self.__lineno_to_ea(stmt.expr.value), 32)

    return

  def generate_statements(self, ea):
    """ this is where the magic happens, this method yeilds one or more new
    statement corresponding to the given location. """

    stmt = self.__stmt(ea)
    if type(stmt) == ir_parser.conditional_goto_t:
      true = value_t(self.__lineno_to_ea(stmt.loc), 32)
      false = value_t(self.next_instruction_ea(ea), 32)
      cond = stmt.cond
      yield branch_t(ea, cond, true, false)
    elif type(stmt) == goto_t:
      stmt.expr.value = self.__lineno_to_ea(stmt.expr.value)
      yield stmt
    else:
      yield stmt

    return

  def get_ea_name(self, ea):
    """ return the name of this location, or None if no name is defined. """
    #~ if ea not in range(len(self.tree)):
        #~ return
    #~ lineno = self.tree[ea][0]
    #~ if lineno is not None:
        #~ return 'loc_%x' % (lineno, )
    for name, method in ir_parser.methods.iteritems():
      if method == ea:
        return name
    return

  def get_string(self, ea):
    """ return the string starting at 'ea' or None if it is not a string. """
    return None

  def function_does_return(self, ea):
    """ return False if the function does not return (ExitThread(), exit(), etc). """
    return True

  def get_function_start(self, ea):
    """ return the address of the parent function, given any address inside that function. """
    if ea not in range(len(self.tree)):
      raise RuntimeError('address not within function')
    return 0

  def get_function_items(self, ea):
    """ return all addresses that belong to the function at 'ea'. """
    if ea not in range(len(self.tree)):
      raise RuntimeError('address not within function')
    return range(len(self.tree))

  def get_instruction_size(self, ea):
    """ return the instruction size. """
    return 1

  def get_mnemonic(self, ea):
    """ return textual mnemonic for the instruction at 'ea'. """
    raise RuntimeError('cannot be called')

  def get_operand_expression(self, ea, n):
    """ return an expression representing the 'n'-th operand of the instruction at 'ea'. """
    raise RuntimeError('cannot be called')

  def get_call_expression(self, ea, insn):
    """ get an expression representing a function call at this address. """
    raise RuntimeError('cannot be called')
