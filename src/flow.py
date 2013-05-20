import idautils
import idaapi
import idc

try:
    reload(dec_types)
except:
    pass

from expressions import *
from statements import *

import filters.simplify_expressions
import filters.controlflow

class flowblock_t(object):
    
    def __init__(self, ea):
        
        self.ea = ea
        
        self.items = []
        self.container = container_t()
        
        self.jump_from = []
        self.jump_to = []
        
        self.branch_expr = None
        
        self.return_expr = None
        self.falls_into = None
        
        return
    
    def __repr__(self):
        return '<flowblock %s>' % (repr(self.container), )
    
    def __str__(self):
        return str(self.container)

STACK_REG =  4
EAX_REG =  0

class flow_t(object):
    
    def __init__(self, entry_ea, follow_calls=True):
        
        self.entry_ea = entry_ea
        self.follow_calls = follow_calls
        
        self.func_items = list(idautils.FuncItems(self.entry_ea))
        
        self.return_blocks = []
        
        self.entry_block = None
        self.blocks = {}
        
        self.signed_limit = 0xf000000000000000 # for 64bits ..
        self.max_int = 0xffffffffffffffff # for 64bits ..
        self.stackreg = regloc_t(STACK_REG)
        self.resultreg = regloc_t(EAX_REG)
        
        self.flow_break = ['retn', ] # unstructions that break (terminate) the flow
        self.unconditional_jumps = ['jmp', ]
        self.conditional_jumps = ['jz', 'jnz', 'jnb', 'ja', 'jg', 'jb', 'jbe', 'jle' ]
        
        self.find_control_flow()
        
        return
    
    def __repr__(self):
        
        lines = []
        
        for block in self.iterblocks():
            lines.append('<loc_%x>' % (block.ea, ))
            
            lines += repr(block.container).split('\n')
            
            lines.append('')
        
        return '\n'.join(lines)
    
    def __str__(self):
        
        lines = []
        
        #~ proto = 'sub_%x(%s)' % (self.entry_block.ea, ', '.join([str(a) for a in self.args]))
        proto = 'sub_%x()' % (self.entry_block.ea, )
        
        for block in self.iterblocks():
            
            if block.jump_from:
                lines.append('')
                lines.append('loc_%x:' % (block.ea, ))
            
            s = str(block.container)
            #~ s = '   ' + ('\n   '.join(s.split('\n')))
            lines.append(s)
        
        txt = '\n'.join(lines)
        
        return '%s {\n%s\n}' % (proto, txt)
    
    def remove_goto(self, block, stmt):
        """ remove a goto statement, and take care of unlinking the 
            jump_to and jump_from.
            
            'block' is the block which contains the goto.
            'stmt' is the goto statement.
        """
        
        if type(stmt.expr) == value_t:
            dst_ea = stmt.expr.value
            dst_block = self.blocks[dst_ea]
            dst_block.jump_from.remove(block)
            block.jump_to.remove(dst_block)
        
        stmt.container.remove(stmt)
        return
    
    def jump_targets(self):
        """ find each point in the function which is the target of a jump (conditional or not) """
        
        for item in idautils.FuncItems(self.entry_ea):
            
            insn = idautils.DecodeInstruction(item)
            mnem = idc.GetMnem(item)
            
            if mnem in self.unconditional_jumps:
                if insn.Op1.type == 2:
                    ea = idc.Qword(insn.Op1.addr)
                else:
                    ea = insn.Op1.addr
                yield ea
            elif mnem in self.conditional_jumps:
                ea = insn.Op1.addr
                yield ea
                ea = item + insn.size
                yield ea
        
        return
    
    def find_control_flow(self):
        
        # find all jump targets
        jump_targets = list(set(self.jump_targets()))
        #~ print 'targets', repr([hex(ea) for ea in jump_targets])
        
        # prepare first block
        self.entry_block = flowblock_t(self.entry_ea)
        next_blocks = [self.entry_block, ]
        self.blocks[self.entry_ea] = self.entry_block
        
        # create all empty blocks.
        for target in jump_targets:
            block = flowblock_t(target)
            self.blocks[target] = block
            next_blocks.append(block)
        
        while len(next_blocks) > 0:
            
            # get next block
            block = next_blocks.pop(0)
            ea = block.ea
            
            while True:
                # append current ea to the block's locations array
                block.items.append(ea)
                
                mnem = idc.GetMnem(ea)
                insn = idautils.DecodeInstruction(ea)
                assert insn.size > 0
                
                if mnem in self.flow_break:
                    
                    self.return_blocks.append(block)
                    break
                
                if mnem in self.unconditional_jumps:
                    
                    if insn.Op1.type == 2:
                        # jmp to [offset]
                        ea = idc.Qword(insn.Op1.addr)
                        if ea == self.max_int:
                            raise RuntimeError("can't resolve jump target *(%x)" % insn.Op1.addr)
                    
                    elif  insn.Op1.type == 7:
                        ea = insn.Op1.addr
                        
                    else:
                        raise RuntimeError("don't know how to follow jump type %s" % insn.Op1.type)
                    
                    if ea not in self.func_items:
                        print 'jumped outside of function: %x' % (block.ea, )
                        self.return_blocks.append(block)
                    else:
                        toblock = self.blocks[ea]
                        block.jump_to.append(toblock)
                        toblock.jump_from.append(block)
                    
                    break
                
                elif mnem in self.conditional_jumps:
                    
                    #~ print repr(mnem)
                    for ea_to in (insn.Op1.addr, ea + insn.size):
                        
                        if ea_to not in self.func_items:
                            print 'jumped outside of function: %x' % (block.ea, )
                        else:
                            toblock = self.blocks[ea_to]
                            block.jump_to.append(toblock)
                            toblock.jump_from.append(block)
                    
                    break
                
                ea += insn.size
                
                if ea not in self.func_items:
                    print 'jumped outside of function: %x' % (block.ea, )
                    break
                
                # the next instruction is part of another block...
                if ea in jump_targets:
                    toblock = self.blocks[ea]
                    block.jump_to.append(toblock)
                    toblock.jump_from.append(block)
                    
                    block.falls_into = toblock
                    break
        
        return
    
    def iterblocks(self):
        """ iterate over all blocks in the order that they most logically follow each other. """
        done = []
        blocks = [self.entry_block, ]
        
        while len(blocks) > 0:
            
            block = blocks.pop(0)
            
            if block in done:
                continue
            
            done.append(block)
            
            yield block
            
            for block in block.jump_to:
                if block not in done:
                    if block in blocks:
                        # re-add at the end
                        blocks.remove(block)
                    blocks.append(block)
        
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
    
    def get_operand(self, block, ea, op):
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
    
    def get_function_call(self, block, ea, insn):
        
        fct = self.get_operand(block, ea, insn.Op1)
        
        if type(fct) == value_t and \
                idc.GetFunctionFlags(fct.value) & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:
            
            print '%x: call to function thunk %x' % (ea, fct.value)
            
            #~ proto = idaapi.idc_get_type(fct.value)
            #~ assert '(' in proto and ')' in proto
            
            #~ args = 
            
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
            #~ params = [(self.get_value_at(block, p) or p) for p in params]
            expr = call_t(fct, None)
        
        #~ for spoil in spoils:
            #~ block.registers.remove(spoil)
        
        # check if eax is a spoiled register for the target function.
        # if it is, change the expression into an assignment to eax
        
        if type(fct) != value_t or not (idc.GetFunctionFlags(fct.value) & idaapi.FUNC_NORET):
            expr = assign_t(self.resultreg.copy(), expr)
        
        return expr, spoils
    
    def generate_statements(self, block, ea):
        """ this is where the magic happens, this method yeilds one or more new
        statement corresponding to the given location. """
        
        insn = idautils.DecodeInstruction(ea)
        mnem = idc.GetMnem(ea)
        
        expr = None
        
        if mnem == 'nop':
            
            pass
            
        elif mnem == "push":
            
            op = self.get_operand(block, ea, insn.Op1)
            
            # stack location assignment
            expr = assign_t(deref_t(self.stackreg.copy()), op.copy())
            yield expr
            
            # stack pointer modification
            expr = assign_t(self.stackreg.copy(), sub_t(self.stackreg.copy(), value_t(4)))
            yield expr
            
        elif mnem == "pop":
            assert insn.Op1.type == 1
            
            # stack pointer modification
            expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), value_t(4)))
            yield expr
            
            # stack location value
            dst = self.get_operand(block, ea, insn.Op1)
            
            expr = assign_t(dst.copy(), deref_t(self.stackreg.copy()))
            yield expr
            
        elif mnem == "leave":
            
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
            
        elif mnem in ("add", "sub"):
            #~ assert insn.Op1.type == 1
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            _type = add_t if mnem == "add" else sub_t
            expr = assign_t(op1.copy(), _type(op1, op2))
            yield expr
            
        elif mnem == "call":
            # call is a special case: we analyse the target functions's flow to determine
            # the likely parameters.
            
            expr, spoils = self.get_function_call(block, ea, insn)
            yield expr
            
        elif mnem == "lea":
            assert insn.Op1.type == 1
            
            dst = self.get_operand(block, ea, insn.Op1)
            op = self.get_operand(block, ea, insn.Op2)
            
            expr = assign_t(dst, address_t(op))
            yield expr
            
        elif mnem == "xor":
            #~ assert insn.Op1.type == 1
            #~ assert insn.Op2.type == 1
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            xor = xor_t(op1, op2)
            expr = assign_t(op1.copy(), xor)
            block.branch_expr = xor
            yield expr
            
        elif mnem == "and":
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            expr = assign_t(op1.copy(), and_t(op1, op2))
            yield expr
            
        elif mnem == "or":
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            expr = assign_t(op1.copy(), or_t(op1, op2))
            yield expr
            
        elif mnem in ('shl', 'shr'):
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            cls = shr_t if mnem == 'shr' else shl_t
            expr = assign_t(op1.copy(), cls(op1, op2))
            yield expr
            
        elif mnem == "hlt":
            
            
            pass
            
        elif mnem in ('mov', 'movzx'):
            
            dst = self.get_operand(block, ea, insn.Op1)
            op = self.get_operand(block, ea, insn.Op2)
            
            expr = assign_t(dst, op)
            yield expr
            
        elif mnem in ("inc", "dec"):
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = value_t(1)
            
            _type = add_t if mnem == 'inc' else sub_t
            expr = assign_t(op1.copy(), _type(op1, op2))
            yield expr
            
        elif mnem == "retn":
            assert insn.Op1.type in (0, 5)
            
            if insn.Op1.type == 5:
                # stack pointer adjusted from return
                op = self.get_operand(block, ea, insn.Op1)
                expr = assign_t(self.stackreg.copy(), add_t(self.stackreg.copy(), op))
                yield expr
            
            expr = return_t(self.resultreg.copy())
            yield expr
            
            block.return_expr = expr
        
        elif mnem == 'cmp':
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            #~ expr = equals_t(sub_t(op1, op2), value_t(0))
            
            # yield this expression so it can be simplified now but stored for later use
            block.branch_expr = cmp_t(op1, op2)
            
        elif mnem == 'test':
            
            op1 = self.get_operand(block, ea, insn.Op1)
            op2 = self.get_operand(block, ea, insn.Op2)
            
            #~ expr = equals_t(sub_t(op1, op2), value_t(0))
            
            # yield this expression so it can be simplified now but stored for later use
            block.branch_expr = test_t(op1, op2)
            
        elif mnem == 'jmp':
            # control flow instruction...
            #~ raise RuntimeError('there should not be a jmp...')
            
            dst = self.get_operand(block, ea, insn.Op1)
            
            
            if type(dst) == value_t and idaapi.get_func(dst.value) and \
                    idaapi.get_func(dst.value).startEA == dst.value:
                # target of jump is a function.
                # let's assume that this is tail call optimization.
                
                expr = return_t(call_t(dst, None))
                yield expr
                
                block.block_expr = expr
                
            else:
                expr = goto_t(dst)
                yield expr
        
        elif mnem in ('jz', 'jnz'):
            
            assert block.branch_expr is not None, 'at %x' % ea
            
            if mnem == 'jz':
                cond = block.branch_expr.zf()
            elif mnem == 'jnz':
                cond = not_t(block.branch_expr.zf())
            
            dst = self.get_operand(block, ea, insn.Op1)
            goto = goto_t(dst)
            
            then = container_t([goto, ])
            
            expr = if_t(cond, then)
            yield expr
            
            # add goto for false side of condition
            
            dst = value_t(ea + insn.size)
            expr = goto_t(dst)
            yield expr
            
        elif mnem in ('jg', 'ja', 'jnb', 'jb', 'jle', 'jbe'):
            # we do not distinguish between signed and unsigned comparision here.
            
            assert type(block.branch_expr) == cmp_t, 'at %x' % ea
            
            op1, op2 = block.branch_expr.op1, block.branch_expr.op2
            
            if mnem in ('jb', ):
                cond = lower_t(op1.copy(), op2.copy())
            elif mnem in ('ja', 'jnb', 'jg'):
                cond = above_t(op1.copy(), op2.copy())
            elif mnem in ('jle', 'jbe'):
                cond = leq_t(op1.copy(), op2.copy())
            
            dst = self.get_operand(block, ea, insn.Op1)
            goto = goto_t(dst)
            
            then = container_t([goto, ])
            
            expr = if_t(cond, then)
            yield expr
            
            # add goto for false side of condition
            
            dst = value_t(ea + insn.size)
            expr = goto_t(dst)
            yield expr
            
        else:
            raise RuntimeError('%x: not yet handled instruction: %s ' % (ea, mnem))
        
        return
    
    def simplify_expressions(self, expr):
        """ combine expressions until it cannot be combined any more. return the new expression. """
        
        return filters.simplify_expressions.run(expr)
    
    def simplify_statement(self, stmt):
        """ find any expression present in a statement and simplify them. if the statement
            has other statements nested (as is the case for if-then, while, etc), then 
            sub-statements are also processed. """
        
        # simplify sub-statements
        for _stmt in stmt.statements:
            self.simplify_statement(_stmt)
        
        stmt.expr = self.filter_expression(stmt.expr, self.simplify_expressions)
        return stmt
    
    def prepare_statement(self, item):
        """ always return a statement from an expression or a statement. """
        
        if isinstance(item, statement_t):
            stmt = item
        elif isinstance(item, expr_t):
            stmt = statement_t(item)
        else:
            raise RuntimeError("don't know how to make a statement with %s" % (repr(item), ))
        
        # tag left-side expression of assignment as being a definition.
        #~ if type(stmt.expr) == assign_t and type(stmt.expr.op1) == regloc_t:
            #~ stmt.expr.op1.is_def = True
            #~ print str(stmt.expr.op1), 'is def in', str(stmt.expr)
        
        return stmt
    
    def prepare_blocks(self):
        """ put blocks in something close to ssa form. """
        
        for block in self.iterblocks():
            
            # for all item in the block, process each statement.
            for item in block.items:
                for expr in self.generate_statements(block, item):
                    
                    # upgrade expr to statement if necessary
                    stmt = self.prepare_statement(expr)
                    
                    # apply simplification rules to all expressions in this statement
                    stmt = self.simplify_statement(stmt)
                    
                    block.container.add(stmt)
            
            # if the block 'falls' without branch instruction into another one, add a goto for clarity
            if block.falls_into:
                block.container.add(goto_t(value_t(block.falls_into.ea)))
        
        return
    
    def filter_expression(self, expr, filter):
        """ recursively call the 'filter' function over all operands of all expressions
            found in 'expr', depth first. """
        
        if type(expr) == assign_t:
            expr.op1 = self.filter_expression(expr.op1, filter)
            expr.op2 = self.filter_expression(expr.op2, filter)
        
        elif isinstance(expr, expr_t):
            
            for i in range(len(expr)):
                op = expr[i]
                if op is None:
                    continue
                
                expr[i] = self.filter_expression(expr[i], filter)
        
        elif type(expr) in (value_t, regloc_t, var_t, arg_t):
            pass
        
        else:
            #~ print repr(expr)
            raise RuntimeError('cannot iterate over expression of type %s' % (type(expr), ))
        
        expr = filter(expr)
        return expr
    
    def combine_blocks(self):
        
        filters.controlflow.run(self)
        
        return
