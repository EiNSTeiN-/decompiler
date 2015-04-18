""" support for Capstone's intel assembly. """

import capstone

from expressions import *
from statements import *

class disassembler(object):

  def __init__(self):
    self.strings = {}
    self.names = {}
    self.md.detail = True
    self.instructions = {i.address: i for i in self.md.disasm(self.code, self.ea)}
    return

  def add_name(self, ea, name):
    self.names[ea] = name
    return

  def add_string(self, ea, string):
    self.strings[ea] = string
    return

  def get_ea_name(self, ea):
    """ return the name of this location, or None if no name is defined. """
    if ea in self.names:
      return self.names[ea]

  def get_string(self, ea):
    """ return the string starting at 'ea' or None if it is not a string. """
    if ea in self.strings:
      return self.strings[ea]

  def function_does_return(self, ea):
    """ return False if the function does not return (ExitThread(), exit(), etc). """
    return True

  def get_function_start(self, ea):
    """ return the address of the parent function, given any address inside that function. """
    return self.ea

  def get_function_items(self, ea):
    """ return all addresses that belong to the function at 'ea'. """
    return list(self.instructions.keys())

  def get_mnemonic(self, ea):
    """ return textual mnemonic for the instruction at 'ea'. """
    return self.instructions[ea].mnemonic

  def get_instruction_size(self, ea):
    """ return the instruction size. """
    return self.instructions[ea].size

  def __reg_index(self, which):
    """ returns the IR index of the register from the capstone index. """
    name = capstone._cs.cs_reg_name(self.md.csh, which)
    return self.get_regindex(name)

  def get_operand_expression(self, ea, n):
    """ return an expression representing the 'n'-th operand of the instruction at 'ea'. """

    insn = self.instructions[ea]
    op = insn.operands[n]

    if op.type == capstone.x86.X86_OP_REG:
      expr = regloc_t(self.__reg_index(op.reg), op.size*8, name=insn.reg_name(op.reg))
    elif op.type == capstone.x86.X86_OP_MEM:

      base, index, scale, disp = (None,)*4

      if op.mem.base:
        base = regloc_t(self.__reg_index(op.mem.base), op.size*8, name=insn.reg_name(op.mem.base))

      if op.mem.index:
        index = regloc_t(self.__reg_index(op.mem.index), op.size*8, name=insn.reg_name(op.mem.index))

      if op.mem.scale > 1:
        scale = value_t(op.mem.scale, op.size*8)

      if op.mem.disp:
        disp = value_t(op.mem.disp, op.size*8)

      if base and index and disp:
        # reg+((reg*idx)+addr)
        index = mul_t(index, scale) if scale else index
        expr = add_t(base, add_t(index, disp))
      elif base and index:
        # reg+(reg*idx)
        index = mul_t(index, scale) if scale else index
        expr = add_t(base, index)
      elif base and disp:
        # reg+addr
        expr = add_t(base, disp)
      elif base:
        # reg
        expr = base
      elif disp:
        # addr
        expr = disp
      else:
        raise RuntimeError('unhandled mem operand')

      expr = deref_t(expr, op.size*8)
    elif op.type == capstone.x86.X86_OP_IMM: #  Immediate Value
      expr = value_t(op.imm, op.size*8)
    else:
      raise RuntimeError('%x: unhandled operand type: %s' % (ea, repr(op.type)))
      return

    return expr

  def get_call_expression(self, ea):
    """ get an expression representing a function call at this address. """
    fct = self.get_operand_expression(ea, 0)
    expr = assign_t(self.resultreg.copy(), call_t(fct, self.stackreg.copy(), params_t()))
    return expr, []
