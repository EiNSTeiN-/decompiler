""" support for IDA's intel assembly. """

import idaapi
import idautils
import idc

from expressions import *
from statements import *

class disassembler(object):

  def __init__(self):
    self.registers_32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
    self.registers_64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12']
    return

  def get_stack_register(self):
    return 4 # esp in ida.

  def get_result_register(self):
    return 0 # eax in ida.

  def get_leave_register(self):
    return 5 # ebp in ida.

  def get_ea_name(self, ea):
    """ return the name of this location, or None if no name is defined. """
    return idc.Name(ea)

  def get_string(self, ea):
    """ return the string starting at 'ea' or None if it is not a string. """
    return idc.GetString(ea)

  def function_does_return(self, ea):
    """ return False if the function does not return (ExitThread(), exit(), etc). """
    if idc.GetFunctionFlags(call.fct.value) & idaapi.FUNC_NORET:
      return False
    return True

  def get_function_start(self, ea):
    """ return the address of the parent function, given any address inside that function. """
    func = idaapi.get_func(ea)
    if func:
      return func.startEA
    return

  def get_function_items(self, ea):
    """ return all addresses that belong to the function at 'ea'. """
    return list(idautils.FuncItems(ea))

  def get_mnemonic(self, ea):
    """ return textual mnemonic for the instruction at 'ea'. """
    return idc.GetMnem(ea)

  def get_regname(self, which):
    ### this is wrong until I can fix it.
    if which <= len(self.registers_32):
      return self.registers_32[which]
    return '#%u' % (which, )

  def get_instruction_size(self, ea):
    """ return the instruction size. """
    insn = idautils.DecodeInstruction(ea)
    assert insn.size > 0, '%x: no instruction' % (ea, )
    return insn.size

  def as_byte_value(self, value):
    if value < 0:
      return 0x100+value
    return value

  def has_sib_byte(self, op):
    # Does the instruction use the SIB byte?
    return self.as_byte_value(op.specflag1) == 1

  def get_sib_scale(self, op):
    return (1, 2, 4, 8)[self.as_byte_value(op.specflag2) >> 6]

  def get_sib_scaled_index_reg(self, op):
    return (self.as_byte_value(op.specflag2) >> 3) & 0x7

  def get_operand_size(self, op):

    types = {
      idaapi.dt_byte: 8,
      idaapi.dt_word: 16,
      idaapi.dt_dword: 32,
      idaapi.dt_float: 32,
      idaapi.dt_double: 64,
      idaapi.dt_qword: 64,
      idaapi.dt_byte16: 64,
      idaapi.dt_fword: 48,
      idaapi.dt_3byte: 48,
    }

    if op.dtyp not in types:
      raise ValueError("don't know how to get the size of this operand")

    return types[op.dtyp]

  def get_operand_expression(self, ea, n):
    """ return an expression representing the 'n'-th operand of the instruction at 'ea'. """

    insn = idautils.DecodeInstruction(ea)
    op = insn[n]

    if op.type == idaapi.o_reg:       #  General Register (al,ax,es,ds...)    reg
      sz = self.get_operand_size(op)
      expr = regloc_t(op.reg, sz, name=self.get_regname(op.reg))

    elif op.type == idaapi.o_mem: #  Direct Memory Reference  (DATA)

      addr = self.as_signed(op.addr)

      if self.has_sib_byte(op):
        reg = self.get_sib_scaled_index_reg(op)
        # *(addr+reg*scale)
        expr = deref_t(add_t(value_t(addr), \
          mul_t(regloc_t(reg, self.get_register_size(reg), name=self.get_regname(reg)), \
            value_t(self.get_sib_scale(op), 8))), self.get_operand_size(op))
      else:
        expr = deref_t(value_t(addr, self.address_size), self.get_operand_size(op))

    elif op.type == idaapi.o_phrase: #  Memory Ref [Base Reg + Index Reg]

      expr = regloc_t(op.reg, self.get_register_size(op.reg), name=self.get_regname(op.reg))
      expr = deref_t(expr, self.get_operand_size(op))

    elif op.type == idaapi.o_displ: #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr

      addr = self.as_signed(op.addr)

      expr = regloc_t(op.reg, self.get_register_size(op.reg), name=self.get_regname(op.reg))

      expr = add_t(expr, value_t(addr, self.address_size))
      expr = deref_t(expr, self.get_operand_size(op))

    elif op.type == idaapi.o_imm: #  Immediate Value
      _value = self.as_signed(op.value)
      expr = value_t(_value, self.get_operand_size(op))
    elif op.type == idaapi.o_near: #  Immediate Far Address  (CODE)
      addr = self.as_signed(op.addr)
      expr = value_t(addr, self.get_operand_size(op))
    else:
      raise RuntimeError('%x: unhandled operand type: %s %s' % (ea, repr(op.type), repr(idc.GetOpnd(ea, 1))))
      return

    return expr

  def get_call_expression(self, ea):
    """ get an expression representing a function call at this address. """

    insn = idautils.DecodeInstruction(ea)

    fct = self.get_operand_expression(ea, 0)

    if type(fct) == value_t and \
        idc.GetFunctionFlags(fct.value) & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:

      print '%x: call to function thunk %x' % (ea, fct.value)

      expr = call_t(fct, None)
      #~ return expr, []
      spoils = []

    else:
      #~ if self.follow_calls and type(fct) == value_t:
      if type(fct) == value_t:
        fct_ea = fct.value

        #~ try:
          #~ call_flow = graph_t(fct_ea, follow_calls = False)
          #~ call_flow.reduce_blocks()

          #~ params = [p.copy() for p in call_flow.uninitialized_uses]
          #~ spoils = [p.copy() for p in call_flow.spoils]
        #~ except:

        print '%x could not analyse call to %x' % (ea, fct.value)
        params = []
        spoils = []
      else:
        params = []
        spoils = []

      # for all uninitialized register uses in the target function, resolve to a value.
      #~ params = [(self.get_value_at(p) or p) for p in params]
      expr = call_t(fct, None)

    # check if eax is a spoiled register for the target function.
    # if it is, change the expression into an assignment to eax

    if type(fct) != value_t or not (idc.GetFunctionFlags(fct.value) & idaapi.FUNC_NORET):
      expr = assign_t(self.resultreg.copy(), expr)

    return expr, spoils

