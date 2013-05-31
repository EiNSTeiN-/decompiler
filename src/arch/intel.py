""" intel x86 and x64 archs. """

import idaapi
import idautils
import idc

from expressions import *
from statements import *

from generic import arch_base

STACK_REG =  4
EAX_REG =  0

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


class arch_intel(arch_base):
    
    def __init__(self, ):
        
        self.signed_limit = 0xf000000000000000 # for 64bits ..
        self.max_int = 0xffffffffffffffff # for 64bits ..
        
        self.stackreg = regloc_t(STACK_REG)
        self.resultreg = regloc_t(EAX_REG)
        
        self.special_registers = 9000
        
        self.cf = self.make_special_register('%eflags.cf')
        self.pf = self.make_special_register('%eflags.pf')
        self.af = self.make_special_register('%eflags.af')
        self.zf = self.make_special_register('%eflags.zf')
        self.sf = self.make_special_register('%eflags.sf')
        self.of = self.make_special_register('%eflags.of')
        
        self.flow_break = ['retn', ] # instructions that break (terminate) the flow
        self.unconditional_jumps = ['jmp', ]
        self.conditional_jumps = ['jo', 'jno', 'js', 'jns', 'jz', 'jnz',
                'jb', 'jnb', 'jbe', 'ja', 'jl', 'jge', 'jle', 'jg', 
                'jpe', 'jno']
        
        return
    
    def make_special_register(self, name):
        reg = flagloc_t(self.special_registers, name)
        self.special_registers += 1
        return reg
    
    def is_conditional_jump(self, ea):
        """ return true if this instruction is a conditional jump. """
        
        mnem = idc.GetMnem(ea)
        
        if mnem in self.conditional_jumps:
            return True
        
        return False
    
    def is_unconditional_jump(self, ea):
        """ return true if this instruction is a unconditional jump. """
        
        mnem = idc.GetMnem(ea)
        
        if mnem in self.unconditional_jumps:
            return True
        
        return False
    
    def is_return(self, ea):
        """ return True if this is a return instruction """
        
        mnem = idc.GetMnem(ea)
        
        if mnem in self.flow_break:
            return True
        
        return False
    
    def has_jump(self, ea):
        """ return true if this instruction is a jump """
        
        return self.is_conditional_jump(ea) or self.is_unconditional_jump(ea)
    
    def next_instruction(self, ea):
        insn = idautils.DecodeInstruction(ea)
        assert insn.size > 0, '%x: no instruction' % (ea, )
        return ea + insn.size
    
    def jump_branches(self, ea):
        """ if this instruction is a jump, yield the destination(s)
            of the jump, of which there may be more than one.
            
            only literal destinations (i.e. addresses without dereferences)
            are yielded. """
        
        mnem = idc.GetMnem(ea)
        insn = idautils.DecodeInstruction(ea)
        
        if mnem in self.unconditional_jumps:
            
            if insn.Op1.type == idaapi.o_near:
                
                if insn.Op1.addr > self.signed_limit:
                    dest = - ((self.max_int + 1) - op.addr)
                else:
                    dest = insn.Op1.addr
                
                yield dest
        
        elif mnem in self.conditional_jumps:
            dest = insn.Op1.addr
            yield dest
            dest = ea + insn.size
            yield dest
        
        return
    
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
    
    def get_operand(self, ea, op):
        """ make up an expression representing the operand. """
        
        if op.type == idaapi.o_reg:       #  General Register (al,ax,es,ds...)    reg
            expr = regloc_t(op.reg)
            
        elif op.type == idaapi.o_mem: #  Direct Memory Reference  (DATA)
            
            if op.addr > self.signed_limit:
                addr = - ((self.max_int + 1) - op.addr)
            else:
                addr = op.addr
            
            if self.has_sib_byte(op):
                
                # *(addr+reg*scale)
                expr = deref_t(add_t(value_t(addr), \
                    mul_t(regloc_t(self.get_sib_scaled_index_reg(op)), \
                        value_t(self.get_sib_scale(op)))))
            else:
                expr = deref_t(value_t(addr))
            
            
        elif op.type == idaapi.o_phrase: #  Memory Ref [Base Reg + Index Reg]
            
            expr = regloc_t(op.reg)
            expr = deref_t(expr)
            
        elif op.type == idaapi.o_displ: #  Memory Reg [Base Reg + Index Reg + Displacement] phrase+addr
            
            if op.addr > self.signed_limit:
                addr = - ((self.max_int + 1) - op.addr)
            else:
                addr = op.addr
            
            expr = regloc_t(op.reg)
            
            expr = add_t(expr, value_t(addr))
            expr = deref_t(expr)
            
        elif op.type == idaapi.o_imm: #  Immediate Value
            
            if op.value > self.signed_limit:
                _value = - ((self.max_int + 1) - op.value)
            else:
                _value = op.value
            
            expr = value_t(_value)
        elif op.type == idaapi.o_near: #  Immediate Far Address  (CODE)
            
            if op.addr > self.signed_limit:
                addr = - ((self.max_int + 1) - op.addr)
            else:
                addr = op.addr
            
            expr = value_t(addr)
        else:
            #~ print hex(ea), 
            raise RuntimeError('%x: unhandled operand type: %s %s' % (ea, repr(op.type), repr(idc.GetOpnd(ea, 1))))
            return
        
        return expr
    
    def get_function_call(self, ea, insn):
        
        fct = self.get_operand(ea, insn.Op1)
        
        if type(fct) == value_t and \
                idc.GetFunctionFlags(fct.value) & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:
            
            print '%x: call to function thunk %x' % (ea, fct.value)
            
            expr = call_t(fct, None)
            #~ return expr, []
            spoils = []
        
        else:
            if self.follow_calls and type(fct) == value_t:
                fct_ea = fct.value
                
                try:
                    call_flow = flow_t(fct_ea, follow_calls = False)
                    call_flow.reduce_blocks()
                    
                    params = [p.copy() for p in call_flow.uninitialized_uses]
                    spoils = [p.copy() for p in call_flow.spoils]
                except:
                    
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
    
    def evaluate_flags(self, expr, flags):
        
        if flags & CF:
            yield assign_t(self.cf.copy(), carry_t(expr))
        if flags & PF:
            yield assign_t(self.pf.copy(), parity_t(expr))
        #~ if flags & AF:
            #~ yield assing_t(self.af, overflow_t(sub_t(op1, op2)))
        if flags & ZF:
            yield assign_t(self.zf.copy(), eq_t(expr, value_t(0)))
        if flags & SF:
            yield assign_t(self.sf.copy(), sign_t(expr))
        if flags & OF:
            yield assign_t(self.of.copy(), overflow_t(expr))
        
        return
    
    def clear_flags(self, flags):
        
        if flags & CF:
            yield assign_t(self.cf.copy(), value_t(0))
        if flags & PF:
            yield assign_t(self.pf.copy(), value_t(0))
        if flags & AF:
            yield assign_t(self.af.copy(), value_t(0))
        if flags & ZF:
            yield assign_t(self.zf.copy(), value_t(0))
        if flags & SF:
            yield assign_t(self.sf.copy(), value_t(0))
        if flags & OF:
            yield assign_t(self.of.copy(), value_t(0))
        
        return
    
    def set_flags(self, flags):
        
        if flags & CF:
            yield assign_t(self.cf.copy(), value_t(1))
        if flags & PF:
            yield assign_t(self.pf.copy(), value_t(1))
        if flags & AF:
            yield assign_t(self.af.copy(), value_t(1))
        if flags & ZF:
            yield assign_t(self.zf.copy(), value_t(1))
        if flags & SF:
            yield assign_t(self.sf.copy(), value_t(1))
        if flags & OF:
            yield assing_t(self.of.copy(), value_t(1))
        
        return
    
    def generate_statements(self, ea):
        """ this is where the magic happens, this method yeilds one or more new
        statement corresponding to the given location. """
        
        insn = idautils.DecodeInstruction(ea)
        mnem = idc.GetMnem(ea)
        
        expr = None
        
        if mnem in ('nop', 'hlt'):
            
            pass
            
        elif mnem == 'push':
            
            op = self.get_operand(ea, insn.Op1)
            
            # stack location assignment
            expr = assign_t(deref_t(self.stackreg.copy()), op.copy())
            yield expr
            
            # stack pointer modification
            expr = assign_t(self.stackreg.copy(), sub_t(self.stackreg.copy(), value_t(4)))
            yield expr
            
        elif mnem == 'pop':
            assert insn.Op1.type == 1
            
            # stack pointer modification
            expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), value_t(4)))
            yield expr
            
            # stack location value
            dst = self.get_operand(ea, insn.Op1)
            
            expr = assign_t(dst.copy(), deref_t(self.stackreg.copy()))
            yield expr
            
        elif mnem == 'leave':
            
            # mov esp, ebp
            ebpreg = regloc_t(5)
            expr = assign_t(self.stackreg.copy(), ebpreg.copy())
            yield expr
            
            # stack pointer modification
            expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), value_t(4)))
            yield expr
            
            # stack location value
            expr = assign_t(ebpreg.copy(), deref_t(self.stackreg.copy()))
            yield expr
            
        elif mnem == 'call':
            # call is a special case: we analyse the target functions's flow to determine
            # the likely parameters.
            
            expr, spoils = self.get_function_call(ea, insn)
            yield expr
            
        elif mnem == 'lea':
            assert insn.Op1.type == 1
            
            dst = self.get_operand(ea, insn.Op1)
            op = self.get_operand(ea, insn.Op2)
            
            expr = assign_t(dst, address_t(op))
            yield expr
            
        elif mnem in ('mov', 'movzx'):
            
            dst = self.get_operand(ea, insn.Op1)
            op = self.get_operand(ea, insn.Op2)
            
            expr = assign_t(dst, op)
            yield expr
            
        elif mnem in ('inc', 'dec'):
            choices = {'int': add_t, 'dec': sub_t}
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = value_t(1)
            
            expr = (choices[mnem])(op1, op2)
            
            # CF is unaffected
            for _expr in self.evaluate_flags(expr, PF | AF | ZF | SF | OF):
                yield _expr
            
            yield assign_t(op1.copy(), expr)
            
        elif mnem in ('add', 'sub'):
            choices = {'add': add_t, 'sub': sub_t}
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = self.get_operand(ea, insn.Op2)
            
            expr = (choices[mnem])(op1, op2)
            
            for _expr in self.evaluate_flags(expr, CF | PF | AF | ZF | SF | OF):
                yield _expr
            
            yield assign_t(op1.copy(), expr)
            
        elif mnem == ('xor', 'or', 'and'):
            choices = {'xor': xor_t, 'or': or_t, 'and': and_t}
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = self.get_operand(ea, insn.Op2)
            
            expr = (choices[mnem])(op1, op2)
            
            for _expr in self.clear_flags(CF | OF):
                yield _expr
            # TODO: AF is undefined
            for _expr in self.evaluate_flags(expr, PF | ZF | SF):
                yield _expr
            
            yield assign_t(op1.copy(), expr)
            
        elif mnem in ('shl', 'shr'):
            choices = {'shr': shr_t, 'shl': shl_t}
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = self.get_operand(ea, insn.Op2)
            
            expr = (choices[mnem])(op1, op2)
            
            for _expr in self.evaluate_flags(expr, CF | PF | AF | ZF | SF | OF):
                yield _expr
            
            yield assign_t(op1.copy(), expr)
            
        elif mnem == "retn":
            assert insn.Op1.type in (0, 5)
            
            if insn.Op1.type == 5:
                # stack pointer adjusted from return
                op = self.get_operand(ea, insn.Op1)
                expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), op))
                yield expr
            
            expr = return_t(self.resultreg.copy())
            yield expr
            
            #~ block.return_expr = expr
        
        elif mnem == 'cmp':
            # The comparison is performed by subtracting the second operand from 
            # the first operand and then setting the status flags in the same manner 
            # as the SUB instruction.
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = self.get_operand(ea, insn.Op2)
            
            for expr in self.evaluate_flags(sub_t(op1, op2), CF | PF | AF | ZF | SF | OF):
                yield expr
            
        elif mnem == 'test':
            
            op1 = self.get_operand(ea, insn.Op1)
            op2 = self.get_operand(ea, insn.Op2)
            
            for expr in self.clear_flags(CF | OF):
                yield expr
            
            # TODO: AF is undefined..
            
            for expr in self.evaluate_flags(and_t(op1, op2), PF | ZF | SF):
                yield expr
            
        elif mnem == 'jmp':
            # control flow instruction...
            
            dst = self.get_operand(ea, insn.Op1)
            
            
            if type(dst) == value_t and idaapi.get_func(dst.value) and \
                    idaapi.get_func(dst.value).startEA == dst.value:
                # target of jump is a function.
                # let's assume that this is tail call optimization.
                
                expr = return_t(call_t(dst, None))
                yield expr
                
                #~ block.return_expr = expr
                
            else:
                expr = goto_t(dst)
                yield expr
        
        elif mnem in ('seta', 'setae', 'setb', 'setbe', 'setc', 'sete', 'setg',
                        'setge', 'setl', 'setle', 'setna', 'setnae', 'setbe', 
                        'setnc', 'setne', 'setng', 'setnge', 'setnl', 'setnle',
                        'setno', 'setnp', 'setns', 'setnz', 'seto', 'setp', 
                        'setpe', 'setpo', 'sets', 'setz'):
            
            op1 = self.get_operand(ea, insn.Op1)
            
            # http://faydoc.tripod.com/cpu/setnz.htm
            if mnem == 'seta':
                cond = b_and_t(not_t(self.cf.copy()), not_t(self.zf.copy()))
            elif mnem in ('setae', 'setnb', 'setnc'):
                cond = not_t(self.cf.copy())
            elif mnem in ('setb', 'setc', 'setnae'):
                cond = self.cf.copy()
            elif mnem == 'setbe':
                cond = b_or_t(self.cf.copy(), self.zf.copy())
            elif mnem == 'sete':
                cond = self.zf.copy()
            elif mnem in ('setg', 'setnle'):
                cond = b_and_t(not_t(self.zf.copy()), eq_t(self.sf.copy(), self.of.copy()))
            elif mnem in ('setge', 'setnl'):
                cond = eq_t(self.sf.copy(), self.of.copy())
            elif mnem in ('setl', 'setnge'):
                cond = neq_t(self.sf.copy(), self.of.copy())
            elif mnem in ('setle', 'setng'):
                cond = b_or_t(self.zf.copy(), neq_t(self.sf.copy(), self.of.copy()))
            elif mnem == 'setna':
                cond = b_or_t(self.cf.copy(), self.zf.copy())
            elif mnem == 'setnbe':
                cond = b_and_t(not_t(self.cf.copy()), not_t(self.zf.copy()))
            elif mnem in ('setnz', 'setne'):
                cond = not_t(self.zf.copy())
            elif mnem in ('setno', ):
                cond = not_t(self.of.copy())
            elif mnem in ('setnp', 'setpo'):
                cond = not_t(self.pf.copy())
            elif mnem in ('setns', ):
                cond = not_t(self.sf.copy())
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
                cond = not_t(self.sf.copy())
            elif mnem == 'js':
                # jump if sign bit is set
                cond = self.sf.copy()
            elif mnem == 'jnz': # jne
                # jump if zero bit is clear
                cond = not_t(self.zf.copy())
            elif mnem == 'jz': # je
                # jump if zero bit is set
                cond = self.zf.copy()
            elif mnem == 'jno':
                # jump if overflow bit is clear
                cond = not_t(self.of.copy())
            elif mnem == 'jo':
                # jump if overflow bit is set
                cond = self.of.copy()
            elif mnem == 'jnb': # jae jnc
                # jump if carry bit is clear
                cond = not_t(self.cf.copy())
            elif mnem == 'jb': # jnae jc
                # jump if carry bit is set
                cond = self.cf.copy()
            elif mnem == 'jbe': # jna
                # jump if below or equal
                cond = b_or_t(self.cf.copy(), self.zf.copy())
            elif mnem == 'ja': # jnbe
                # jump if above
                cond = b_and_t(not_t(self.cf.copy()), not_t(self.zf.copy()))
            elif mnem == 'jl': # jnge
                # jump if above
                cond = neq_t(self.sf.copy(), self.of.copy())
            elif mnem == 'jge': # jnl
                # jump if greater or equal
                cond = eq_t(self.sf.copy(), self.of.copy())
            elif mnem == 'jle': # jng
                # jump if less or equal
                cond = b_or_t(self.zf.copy(), neq_t(self.sf.copy(), self.of.copy()))
            elif mnem == 'jg': # jnle
                # jump if greater
                cond = b_and_t(not_t(self.zf.copy()), eq_t(self.sf.copy(), self.of.copy()))
            elif mnem == 'jpe': # jp
                # jump if parity even
                cond = self.pf.copy()
            elif mnem == 'jpo': # jnp
                # jump if parity odd
                cond = not_t(self.pf.copy())
            else:
                raise RuntimeError('unknown jump mnemonic')
            
            dst = self.get_operand(ea, insn.Op1)
            goto = goto_t(dst)
            
            expr = if_t(cond, container_t([goto, ]))
            yield expr
            
            # add goto for false side of condition
            
            dst = value_t(ea + insn.size)
            expr = goto_t(dst)
            yield expr
            
        else:
            raise RuntimeError('%x: not yet handled instruction: %s ' % (ea, mnem))
        
        return
    