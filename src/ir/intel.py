""" intel x86 and x64 archs. """

from collections import namedtuple

from expressions import *
from statements import *

from generic import ir_base

from . import *

# FLAGS
CF =    1 << 0  # carry flag: Set on high-order bit carry or borrow
PF =    1 << 2  # parity flag:
AF =    1 << 4  # adjust flag
ZF =    1 << 6  # zero flag: set if expr == 0
SF =    1 << 7  # sign flag
#~ TF =    1 << 8  # trap flag
#~ IF =    1 << 9  # interrupt enable flag
#~ DF =    1 << 10 # direction flag
OF =    1 << 11 # overflow flag: set when the expression would overflow

# EFLAGS
#~ RF =    1 << 16 # resume flags
#~ VM =    1 << 17 # virtual 8086 mode flag
#~ AC =    1 << 18 # alignment check
#~ VIP =   1 << 19 # virtual interrupt flag
#~ VIF =   1 << 20 # virtual interrupt pending
ID =    1 << 21 # able to use CPUID instruction

SIZE_8 = 8
SIZE_16 = 16
SIZE_32 = 32
SIZE_64 = 64

LOBYTE = 0
HIBYTE = 1
WORD = 2
DWORD = 3
QWORD = 4

register_t = namedtuple('register_t', ['name', 'size', 'type'])
registers = {}

for name in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rip', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
  registers[name] = register_t(name, SIZE_64, QWORD)

for name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eip', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'):
  registers[name] = register_t(name, SIZE_32, DWORD)

for name in ('ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'ip', 'sp', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'):
  registers[name] = register_t(name, SIZE_16, WORD)

for name in ('ah', 'bh', 'ch', 'dh'):
  registers[name] = register_t(name, SIZE_8, HIBYTE)

for name in ('al', 'bl', 'cl', 'dl', 'sil', 'dil', 'bpl', 'spl', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'):
  registers[name] = register_t(name, SIZE_8, LOBYTE)

register_groups = []
register_groups.append(('rax', 'eax', 'ax', 'ah', 'al'))
register_groups.append(('rbx', 'ebx', 'bx', 'bh', 'bl'))
register_groups.append(('rcx', 'ecx', 'cx', 'ch', 'cl'))
register_groups.append(('rdx', 'edx', 'dx', 'dh', 'dl'))
register_groups.append(('rsi', 'esi', 'si', 'sil'))
register_groups.append(('rdi', 'edi', 'di', 'dil'))
register_groups.append(('rbp', 'ebp', 'bp', 'bpl'))
register_groups.append(('rip', 'eip', 'ip'))
register_groups.append(('rsp', 'esp', 'sp', 'spl'))
register_groups.append(('r8', 'r8d', 'r8w', 'r8b'))
register_groups.append(('r9', 'r9d', 'r9w', 'r9b'))
register_groups.append(('r10', 'r10d', 'r10w', 'r10b'))
register_groups.append(('r11', 'r11d', 'r11w', 'r11b'))
register_groups.append(('r12', 'r12d', 'r12w', 'r12b'))
register_groups.append(('r13', 'r13d', 'r13w', 'r13b'))
register_groups.append(('r14', 'r14d', 'r14w', 'r14b'))
register_groups.append(('r15', 'r15d', 'r15w', 'r15b'))

class ir_intel(ir_base):

  def __init__(self):

    assert type(self) != ir_intel, 'must use base classes instead'

    ir_base.__init__(self)

    r = self.get_stack_register()
    self.stackreg = regloc_t(r, self.address_size, name=self.get_regname(r))
    r = self.get_leave_register()
    self.leavereg = regloc_t(r, self.address_size, name=self.get_regname(r))
    r = self.get_result_register()
    self.resultreg = regloc_t(r, self.address_size, name=self.get_regname(r))

    self.special_registers = 9000

    self.eflags_expr = self.make_special_register('%eflags.expr')
    self.cf = self.make_special_register('%eflags.cf')
    self.pf = self.make_special_register('%eflags.pf')
    self.af = self.make_special_register('%eflags.af')
    self.zf = self.make_special_register('%eflags.zf')
    self.sf = self.make_special_register('%eflags.sf')
    self.of = self.make_special_register('%eflags.of')

    self.flow_break = ['retn', 'ret' ] # instructions that break (terminate) the flow
    self.unconditional_jumps = ['jmp', ] # unconditional jumps (one branch)
    self.conditional_jumps = ['jo', 'jno', 'js', 'jns', 'jz', 'je', 'jnz', 'jne',
            'jb', 'jnb', 'jbe', 'ja', 'jl', 'jge', 'jle', 'jg',
            'jpe', 'jno'] # conditional jumps (two branches)

    return

  def get_regindex(self, name):
    if name.lower() in registers:
      return registers.keys().index(name.lower())

  def get_regname(self, which):
    if which < len(registers):
      name = registers.keys()[which]
    else:
      name = '#%u' % (which, )
    return name

  def get_stack_register(self):
    if self.ir_id == IR_INTEL_x86:
      return self.get_regindex('esp')
    elif self.ir_id == IR_INTEL_x64:
      return self.get_regindex('rsp')

  def get_result_register(self):
    if self.ir_id == IR_INTEL_x86:
      return self.get_regindex('eax')
    elif self.ir_id == IR_INTEL_x64:
      return self.get_regindex('rax')

  def get_leave_register(self):
    if self.ir_id == IR_INTEL_x86:
      return self.get_regindex('ebp')
    elif self.ir_id == IR_INTEL_x64:
      return self.get_regindex('rbp')

  def make_special_register(self, name):
    reg = flagloc_t(self.special_registers, 1, name)
    self.special_registers += 1
    return reg

  def is_stackreg(self, reg):
    """ return True if the register is the stack register """
    return isinstance(reg, regloc_t) and reg.no_index_eq(self.stackreg)

  def is_stackvar(self, expr):
    return ((type(expr) in (sub_t, add_t) and \
            (self.is_aligned_stackvar(expr.op1) or self.is_stackreg(expr.op1)) \
              and type(expr.op2) == value_t))

  def is_aligned_stackvar(self, expr):
    return type(expr) == and_t and \
            type(expr.op2) == value_t and \
            type(expr.op1) in (sub_t, add_t) and \
            self.is_stackreg(expr.op1.op1) and type(expr.op1.op2) == value_t

  def is_conditional_jump(self, ea):
    """ return true if this instruction is a conditional jump. """
    mnem = self.get_mnemonic(ea)
    if mnem in self.conditional_jumps:
      return True
    return False

  def is_unconditional_jump(self, ea):
    """ return true if this instruction is a unconditional jump. """
    mnem = self.get_mnemonic(ea)
    if mnem in self.unconditional_jumps:
      return True
    return False

  def is_return(self, ea):
    """ return True if this is a return instruction """
    mnem = self.get_mnemonic(ea)
    if mnem in self.flow_break:
      return True
    return False

  def has_jump(self, ea):
    """ return true if this instruction is a jump """
    return self.is_conditional_jump(ea) or self.is_unconditional_jump(ea)

  def next_instruction_ea(self, ea):
    """ return the address of the next instruction. """
    size = self.get_instruction_size(ea)
    assert size > 0, '%x: no instruction' % (ea, )
    return ea + size

  def jump_branches(self, ea):
    mnem = self.get_mnemonic(ea)
    if mnem in self.unconditional_jumps:
      dest = self.get_operand_expression(ea, 0)
      yield dest
    elif mnem in self.conditional_jumps:
      dest = self.get_operand_expression(ea, 0)
      yield dest
      dest = self.next_instruction_ea(ea)
      yield value_t(dest, self.address_size)
    return

  def as_signed(self, v, size=None):
    if size is None:
      size = self.address_size
    if v > (1 << size-1):
      return - ((sum([1 << i for i in range(size)]) + 1) - v)
    return v

  def evaluate_flags(self, expr, flags):
    yield assign_t(self.eflags_expr.copy(), expr.copy())
    if flags & CF:
      yield assign_t(self.cf.copy(), carry_t(self.eflags_expr.copy()))
    if flags & PF:
      yield assign_t(self.pf.copy(), parity_t(self.eflags_expr.copy()))
    if flags & AF:
      yield assign_t(self.af.copy(), adjust_t(self.eflags_expr.copy()))
    if flags & ZF:
      yield assign_t(self.zf.copy(), eq_t(self.eflags_expr.copy(), value_t(0, 1)))
    if flags & SF:
      yield assign_t(self.sf.copy(), sign_t(self.eflags_expr.copy()))
    if flags & OF:
      yield assign_t(self.of.copy(), overflow_t(self.eflags_expr.copy()))
    return

  def set_flags(self, flags, value):
    if flags & CF:
      yield assign_t(self.cf.copy(), value_t(value, 1))
    if flags & PF:
      yield assign_t(self.pf.copy(), value_t(value, 1))
    if flags & AF:
      yield assign_t(self.af.copy(), value_t(value, 1))
    if flags & ZF:
      yield assign_t(self.zf.copy(), value_t(value, 1))
    if flags & SF:
      yield assign_t(self.sf.copy(), value_t(value, 1))
    if flags & OF:
      yield assign_t(self.of.copy(), value_t(value, 1))
    return

  def generate_statements(self, ea):

    mnem = self.get_mnemonic(ea)

    expr = None

    if mnem in ('nop', 'hlt'):
      pass

    elif mnem in ('cdq', 'cdqe'):
      # sign extension... not supported until we do type analysis
      pass

    elif mnem == 'push':

      op = self.get_operand_expression(ea, 0)

      # stack location assignment
      expr = assign_t(deref_t(self.stackreg.copy(), self.address_size), op.copy())
      yield expr

      # stack pointer modification
      expr = assign_t(self.stackreg.copy(), sub_t(self.stackreg.copy(), value_t(4, self.address_size)))
      yield expr

    elif mnem == 'pop':
      #~ assert insn.Op1.type == 1

      # stack pointer modification
      expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), value_t(4, self.address_size)))
      yield expr

      # stack location value
      dst = self.get_operand_expression(ea, 0)

      expr = assign_t(dst.copy(), deref_t(self.stackreg.copy(), self.address_size))
      yield expr

    elif mnem == 'leave':

      # mov esp, ebp
      expr = assign_t(self.stackreg.copy(), self.leavereg.copy())
      yield expr

      # stack pointer modification
      expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), value_t(4, self.address_size)))
      yield expr

      # stack location value
      expr = assign_t(self.leavereg.copy(), deref_t(self.stackreg.copy(), self.address_size))
      yield expr

    elif mnem == 'call':
      # call is a special case: we analyse the target functions's flow to determine
      # the likely parameters.

      expr, spoils = self.get_call_expression(ea)
      yield expr

    elif mnem == 'lea':
      #~ assert insn.Op1.type == 1

      dst = self.get_operand_expression(ea, 0)
      op = self.get_operand_expression(ea, 1)

      expr = assign_t(dst, address_t(op))
      yield expr

    elif mnem == 'not':

      op = self.get_operand_expression(ea, 0)

      expr = assign_t(op.copy(), not_t(op))
      yield expr

    elif mnem == 'neg':

      op = self.get_operand_expression(ea, 0)

      expr = assign_t(op.copy(), neg_t(op))
      yield expr

    elif mnem in ('mov', 'movzx', 'movsxd', 'movsx'):

      dst = self.get_operand_expression(ea, 0)
      op = self.get_operand_expression(ea, 1)

      expr = assign_t(dst, op)
      yield expr

    elif mnem in ('inc', 'dec'):
      choices = {'inc': add_t, 'dec': sub_t}

      op1 = self.get_operand_expression(ea, 0)
      op2 = value_t(1, self.address_size)

      expr = (choices[mnem])(op1, op2)

      # CF is unaffected
      for _expr in self.evaluate_flags(expr, PF | AF | ZF | SF | OF):
        yield _expr

      yield assign_t(op1.copy(), expr)

    elif mnem in ('add', 'sub'):
      choices = {'add': add_t, 'sub': sub_t}

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      expr = (choices[mnem])(op1, op2)

      for _expr in self.evaluate_flags(expr, CF | PF | AF | ZF | SF | OF):
        yield _expr

      yield assign_t(op1.copy(), expr)

    elif mnem in ('imul', ):
      choices = {'imul': mul_t, }

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      expr = (choices[mnem])(op1, op2)

      #~ # TODO: SF, ZF, AF, PF is undefined
      #~ # TODO: CF, OF is defined..

      yield assign_t(op1.copy(), expr)

    elif mnem in ('xor', 'or', 'and'):
      choices = {'xor': xor_t, 'or': or_t, 'and': and_t}

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      expr = (choices[mnem])(op1, op2)

      for _expr in self.set_flags(CF | OF, value=0):
        yield _expr
      # TODO: AF is undefined
      for _expr in self.evaluate_flags(expr, PF | ZF | SF):
        yield _expr

      yield assign_t(op1.copy(), expr)

    elif mnem in ('shl', 'shr', 'sal', 'sar'):
      choices = {'shr': shr_t, 'shl': shl_t, 'sar': shr_t, 'sal': shl_t}

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      expr = (choices[mnem])(op1, op2)

      for _expr in self.evaluate_flags(expr, CF | PF | AF | ZF | SF | OF):
        yield _expr

      yield assign_t(op1.copy(), expr)

    elif mnem in ('retn', 'ret'):
      #~ assert insn.Op1.type in (0, 5)

      #~ if insn.Op1.type == 5:
        #~ # stack pointer adjusted from return
        #~ op = self.get_operand(ea, insn.Op1)
        #~ expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), op))
        #~ yield expr

      expr = return_t(ea, self.resultreg.copy())
      yield expr

    elif mnem == 'cmp':
      # The comparison is performed by subtracting the second operand from
      # the first operand and then setting the status flags in the same manner
      # as the SUB instruction.

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      for expr in self.evaluate_flags(sub_t(op1, op2), CF | PF | AF | ZF | SF | OF):
        yield expr

    elif mnem == 'test':

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      for expr in self.set_flags(CF | OF, value=0):
        yield expr

      # TODO: AF is undefined..

      for expr in self.evaluate_flags(and_t(op1, op2), PF | ZF | SF):
        yield expr

    elif mnem == 'jmp':
      # control flow instruction...

      dst = self.get_operand_expression(ea, 0)

      if type(dst) == value_t and self.get_function_start(dst.value) == dst.value:
        # target of jump is a function.
        # let's assume that this is tail call optimization.

        expr = return_t(ea, call_t(dst, self.resultreg.copy(), params_t()))
        yield expr

        #~ block.return_expr = expr
      else:
        expr = goto_t(ea, dst)
        yield expr

    elif mnem in ('cmova', 'cmovae', 'cmovb', 'cmovbe', 'cmovc', 'cmove', 'cmovg',
                    'cmovge', 'cmovl', 'cmovle', 'cmovna', 'cmovnae', 'cmovbe',
                    'cmovnc', 'cmovne', 'cmovng', 'cmovnge', 'cmovnl', 'cmovnle',
                    'cmovno', 'cmovnp', 'cmovns', 'cmovnz', 'cmovo', 'cmovp',
                    'cmovpe', 'cmovpo', 'cmovs', 'cmovz'):
      # CMOVcc (conditional mov)

      op1 = self.get_operand_expression(ea, 0)
      op2 = self.get_operand_expression(ea, 1)

      if mnem == 'cmova':
        cond = b_and_t(b_not_t(self.zf.copy()), b_not_t(self.cf.copy()))
      elif mnem in ('cmovae', 'cmovnb', 'cmovnc'):
        cond = b_not_t(self.cf.copy())
      elif mnem in ('cmovb', 'cmovc', 'cmovnae'):
        cond = self.cf.copy()
      elif mnem == 'cmovbe':
        cond = b_or_t(self.zf.copy(), self.cf.copy())
      elif mnem == 'cmove':
        cond = self.zf.copy()
      elif mnem in ('cmovg', 'cmovnle'):
        cond = b_and_t(b_not_t(self.zf.copy()), eq_t(self.sf.copy(), self.of.copy()))
      elif mnem in ('cmovge', 'cmovnl'):
        cond = eq_t(self.sf.copy(), self.of.copy())
      elif mnem in ('cmovl', 'cmovnge'):
        cond = neq_t(self.sf.copy(), self.of.copy())
      elif mnem in ('cmovle', 'cmovng'):
        cond = b_or_t(self.zf.copy(), neq_t(self.sf.copy(), self.of.copy()))
      elif mnem == 'cmovna':
        cond = b_or_t(self.zf.copy(), self.cf.copy(), )
      elif mnem == 'cmovnbe':
        cond = b_and_t(b_not_t(self.zf.copy()), b_not_t(self.cf.copy()))
      elif mnem in ('cmovnz', 'cmovne'):
        cond = b_not_t(self.zf.copy())
      elif mnem in ('cmovno', ):
        cond = b_not_t(self.of.copy())
      elif mnem in ('cmovnp', 'cmovpo'):
        cond = b_not_t(self.pf.copy())
      elif mnem in ('cmovns', ):
        cond = b_not_t(self.sf.copy())
      elif mnem in ('cmovo', ):
        cond = self.of.copy()
      elif mnem in ('cmovo', ):
        cond = self.of.copy()
      elif mnem in ('cmovp', 'cmovpe'):
        cond = self.pf.copy()
      elif mnem in ('cmovs', ):
        cond = self.sf.copy()
      elif mnem in ('cmovz', ):
        cond = self.zf.copy()

      expr = assign_t(op1.copy(), ternary_if_t(cond, op2, op1))
      yield expr

    elif mnem in ('seta', 'setae', 'setb', 'setbe', 'setc', 'sete', 'setg',
                    'setge', 'setl', 'setle', 'setna', 'setnae', 'setbe',
                    'setnc', 'setne', 'setng', 'setnge', 'setnl', 'setnle',
                    'setno', 'setnp', 'setns', 'setnz', 'seto', 'setp',
                    'setpe', 'setpo', 'sets', 'setz'):

      op1 = self.get_operand_expression(ea, 0)

      # http://faydoc.tripod.com/cpu/setnz.htm
      if mnem == 'seta':
        cond = b_and_t(b_not_t(self.zf.copy()), b_not_t(self.cf.copy()))
      elif mnem in ('setae', 'setnb', 'setnc'):
        cond = b_not_t(self.cf.copy())
      elif mnem in ('setb', 'setc', 'setnae'):
        cond = self.cf.copy()
      elif mnem == 'setbe':
        cond = b_or_t(self.zf.copy(), self.cf.copy())
      elif mnem == 'sete':
        cond = self.zf.copy()
      elif mnem in ('setg', 'setnle'):
        cond = b_and_t(b_not_t(self.zf.copy()), eq_t(self.sf.copy(), self.of.copy()))
      elif mnem in ('setge', 'setnl'):
        cond = eq_t(self.sf.copy(), self.of.copy())
      elif mnem in ('setl', 'setnge'):
        cond = neq_t(self.sf.copy(), self.of.copy())
      elif mnem in ('setle', 'setng'):
        cond = b_or_t(self.zf.copy(), neq_t(self.sf.copy(), self.of.copy()))
      elif mnem == 'setna':
        cond = b_or_t(self.zf.copy(), self.cf.copy(), )
      elif mnem == 'setnbe':
        cond = b_and_t(b_not_t(self.zf.copy()), b_not_t(self.cf.copy()))
      elif mnem in ('setnz', 'setne'):
        cond = b_not_t(self.zf.copy())
      elif mnem in ('setno', ):
        cond = b_not_t(self.of.copy())
      elif mnem in ('setnp', 'setpo'):
        cond = b_not_t(self.pf.copy())
      elif mnem in ('setns', ):
        cond = b_not_t(self.sf.copy())
      elif mnem in ('seto', ):
        cond = self.of.copy()
      elif mnem in ('seto', ):
        cond = self.of.copy()
      elif mnem in ('setp', 'setpe'):
        cond = self.pf.copy()
      elif mnem in ('sets', ):
        cond = self.sf.copy()
      elif mnem in ('setz', ):
        cond = self.zf.copy()

      expr = assign_t(op1, cond)
      yield expr

    elif mnem in self.conditional_jumps:
      # we do not distinguish between signed and unsigned comparision here.

      if mnem == 'jns':
        # jump if sign bit is clear
        cond = b_not_t(self.sf.copy())
      elif mnem == 'js':
        # jump if sign bit is set
        cond = self.sf.copy()
      elif mnem in ('jnz', 'jne'):
        # jump if zero bit is clear
        cond = b_not_t(self.zf.copy())
      elif mnem in ('jz', 'je'):
        # jump if zero bit is set
        cond = self.zf.copy()
      elif mnem == 'jno':
        # jump if overflow bit is clear
        cond = b_not_t(self.of.copy())
      elif mnem == 'jo':
        # jump if overflow bit is set
        cond = self.of.copy()
      elif mnem == 'jnb': # jae jnc
        # jump if carry bit is clear
        cond = b_not_t(self.cf.copy())
      elif mnem == 'jb': # jnae jc
        # jump if carry bit is set
        cond = self.cf.copy()
      elif mnem == 'jbe': # jna
        # jump if below or equal
        cond = b_or_t(self.zf.copy(), self.cf.copy())
      elif mnem == 'ja': # jnbe
        # jump if above
        cond = b_and_t(b_not_t(self.zf.copy()), b_not_t(self.cf.copy()))
      elif mnem == 'jl': # jnge
        # jump if less
        cond = neq_t(self.sf.copy(), self.of.copy())
      elif mnem == 'jge': # jnl
        # jump if greater or equal
        cond = eq_t(self.sf.copy(), self.of.copy())
      elif mnem == 'jle': # jng
        # jump if less or equal
        cond = b_or_t(self.zf.copy(), neq_t(self.sf.copy(), self.of.copy()))
      elif mnem == 'jg': # jnle
        # jump if greater
        cond = b_and_t(b_not_t(self.zf.copy()), eq_t(self.sf.copy(), self.of.copy()))
      elif mnem == 'jpe': # jp
        # jump if parity even
        cond = self.pf.copy()
      elif mnem == 'jpo': # jnp
        # jump if parity odd
        cond = b_not_t(self.pf.copy())
      else:
        raise RuntimeError('unknown jump mnemonic')

      true = self.get_operand_expression(ea, 0)
      false = value_t(self.next_instruction_ea(ea), self.address_size)

      expr = branch_t(ea, cond, true, false)
      yield expr
    else:
      raise RuntimeError('%x: not yet handled instruction: %s ' % (ea, mnem))

    return

class ir_intel_x86(ir_intel):
  def __init__(self):
    self.address_size = 32
    ir_intel.__init__(self)
    return

  def get_register_size(self, which):
    return 32

class ir_intel_x64(ir_intel):
  def __init__(self):
    self.address_size = 64
    ir_intel.__init__(self)
    return

  def get_register_size(self, which):
    return 64
