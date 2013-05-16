import idautils
import idaapi
import idc

try:
    reload(dec_types)
except:
    pass

from dec_types import *

class flowblock_t(object):
    
    def __init__(self, ea):
        
        self.ea = ea
        
        #~ self.du_chains = defuse_chains()
        
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
    
    def is_normal_flow(self):
        """ non-normal flow branches to one or more locations. """
        return len(self.jump_to) <= 1

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
        
        #~ self.spoils = []
        #~ self.preserves = []
        #~ self.uninitialized_uses = []
        
        #~ self.vars = []
        #~ self.args = []
        
        self.flow_break = ['retn', ] # unstructions that break (terminate) the flow
        self.unconditional_jumps = ['jmp', ]
        self.conditional_jumps = ['jz', 'jnz', 'jb', 'jbe', 'jle' ]
        
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
            return expr, []
        
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
        #~ if self.resultreg in spoils:
        expr = assign_t(self.resultreg.copy(), expr)
        
        return expr, spoils
    
    def get_statements(self, block, ea):
        """ this is where the magic happens, this method yeilds one or more new
        statement corresponding to the given location. """
        
        insn = idautils.DecodeInstruction(ea)
        mnem = idc.GetMnem(ea)
        
        expr = None
        
        if mnem == 'nop':
            
            pass
            
        elif mnem == "push":
            
            dst = self.stackreg
            op = self.get_operand(block, ea, insn.Op1)
            
            # stack location assignment
            expr = assign_t(deref_t(dst), op.copy())
            yield expr
            
            # stack pointer modification
            expr = assign_t(self.stackreg, sub_t(self.stackreg, value_t(4)))
            yield expr
            
        elif mnem == "pop":
            assert insn.Op1.type == 1
            
            # stack pointer modification
            expr = assign_t(self.stackreg, add_t(self.stackreg, value_t(4)))
            yield expr
            
            # stack location value
            dst = self.get_operand(block, ea, insn.Op1)
            
            expr = assign_t(dst.copy(), deref_t(self.stackreg))
            yield expr
            
        elif mnem == "leave":
            
            # mov esp, ebp
            ebpreg = regloc_t(5)
            expr = assign_t(self.stackreg, ebpreg)
            yield expr
            
            # stack pointer modification
            stackptr = self.stackreg
            expr = assign_t(self.stackreg, add_t(stackptr, value_t(4)))
            yield expr
            
            # stack location value
            expr = assign_t(ebpreg, deref_t(self.stackreg))
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
            
        elif mnem == "mov":
            
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
                expr = assign_t(self.stackreg, add_t(self.stackreg, op))
                yield expr
            
            expr = return_t(self.resultreg.copy())
            yield expr
            
            # keep track of spoiled registers at this location (any register that is defined at retn)
            #~ self.spoils += [a.copy() for a,b in block.registers.regs]
            
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
            
        elif mnem in ('jb', 'jle', 'jbe'):
            # we do not distinguish between signed and unsigned comparision here.
            
            assert type(block.branch_expr) == cmp_t, 'at %x' % ea
            
            op1, op2 = block.branch_expr.op1, block.branch_expr.op2
            
            if mnem in ('jb', ):
                cond = lower_t(op1.copy(), op2.copy())
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
    
    def simplify_expressions_inner(self, expr, is_left=False):
        """ this method inpects an expression and determine if it can be 
            simplified in any way. """
        
        if expr.__class__ == add_t and expr.op1.__class__ in (add_t, sub_t) \
                and expr.op1.op2.__class__ == value_t and expr.op2.__class__ == value_t:
            _expr = expr.op1.copy()
            _expr.add(expr.op2)
            return _expr
        
        if expr.__class__ == sub_t and expr.op1.__class__ in (add_t, sub_t) \
                and expr.op1.op2.__class__ == value_t and expr.op2.__class__ == value_t:
            _expr = expr.op1.copy()
            _expr.sub(expr.op2)
            return _expr
        
        if type(expr) in (sub_t, add_t):
            if type(expr.op2) == value_t and expr.op2.value == 0:
                return expr.op1
        
        if type(expr) == address_t and type(expr.op) == deref_t:
            return expr.op.op
        
        if type(expr) == deref_t and type(expr.op) == address_t:
            return expr.op.op
        
        if type(expr) == eq_t and type(expr.op2) == value_t and \
            type(expr.op1) in (sub_t, add_t) and type(expr.op1.op2) == value_t:
            # (<1> - value) == <2> becomes <1> == <2> + value
            if type(expr.op1) == sub_t:
                _value = value_t(expr.op2.value + expr.op1.op2.value)
            else:
                _value = value_t(expr.op2.value - expr.op1.op2.value)
            return eq_t(expr.op1.op1.copy(), _value)
        
        if type(expr) == not_t and type(expr.op) == eq_t:
            return neq_t(expr.op.op1, expr.op.op2)
        
        if type(expr) == not_t and type(expr.op) == neq_t:
            return eq_t(expr.op.op1, expr.op.op2)
        
        if type(expr) == add_t and type(expr.op2) == value_t and expr.op2.value < 0:
            # x + -y becomes x - y
            return sub_t(expr.op1, value_t(abs(expr.op2.value)))
        
        if type(expr) == sub_t and type(expr.op2) == value_t and expr.op2.value < 0:
            # x - -y becomes x + y
            return add_t(expr.op1, value_t(abs(expr.op2.value)))
        
        if type(expr) == not_t and type(expr.op) == not_t:
            # !(!(op)) becomes op
            return expr.op.op
        
        if type(expr) == eq_t and type(expr.op2) == value_t and expr.op2.value == 0:
            # <1> == 0 becomes !(<1>)
            return not_t(expr.op1)
        
        if type(expr) == xor_t and expr.op1 == expr.op2:
            # x ^ x becomes 0
            return value_t(0)
        
        if type(expr) == and_t and expr.op1 == expr.op2:
            # x & x becomes x
            return expr.op1.copy()
        
        return

    def simplify_expressions(self, expr, is_left=False):
        """ combine expressions until it cannot be combined any more. """
        
        while True:
            newexpr = self.simplify_expressions_inner(expr, is_left)
            if newexpr is None:
                break
            expr = newexpr
        
        return expr
    
    def simplify_statement(self, stmt):
        """ find any expression present in a statement and simplify them. """
        
        #~ print repr(stmt)
        for _stmt in stmt.statements:
            if _stmt.expr:
                _stmt.expr = self.filter_recurse(_stmt.expr, self.simplify_expressions)
        
        stmt.expr = self.filter_recurse(stmt.expr, self.simplify_expressions)
        return stmt
    
    def prepare_statement(self, item):
        """ always return a statement from an expression or a statement. """
        
        if isinstance(item, statement_t):
            return item
        elif isinstance(item, expr_t):
            return statement_t(item)
        else:
            raise RuntimeError("don't know how to make a statement with %s" % (repr(item), ))
        
        return
    
    def reduce_blocks(self):
        
        for block in self.iterblocks():
            
            if len(block.jump_from) == 0:
                pass
            elif len(block.jump_from) == 1:
                src_ea = block.jump_from[0].ea
                src_block = self.blocks[src_ea]
                
                #~ block.registers = src_block.registers.copy()
            else:
                
                # this block has multiple paths that lead to it
                # we will remove from its registers list any register that is present in 
                # more than one source paths except if the register has the same value
                # in all source paths.
                
                #~ block.registers = self.mark_spoiled_registers(block)
                pass
            
            # for all item in the block, process each statement.
            for item in block.items:
                for expr in self.get_statements(block, item):
                    
                    # upgrade expr to statement if necessary
                    stmt = self.prepare_statement(expr)
                    
                    # combine all expressions in a statement
                    stmt = self.simplify_statement(stmt)
                    
                    block.container.add(stmt)
            
            # if the block 'falls' without branch instruction into another one, add a goto for clarity
            if block.falls_into:
                block.container.add(goto_t(value_t(block.falls_into.ea)))
        
        #~ self.filter(self.upgrade_variables)
        #~ self.filter(self.upgrade_arguments)
        
        return
    
    def filter_recurse(self, expr, filter, is_left=False):
        """ recursively call the 'filter' function over all operands of all expressions
            found in 'expr', depth first. """
        
        if type(expr) == assign_t:
            expr.op1 = self.filter_recurse(expr.op1, filter, is_left=True)
            expr.op2 = self.filter_recurse(expr.op2, filter, is_left=False)
        
        elif isinstance(expr, expr_t):
            
            for i in range(len(expr.operands)):
                op = expr.operands[i]
                if op is None:
                    continue
                
                expr.operands[i] = self.filter_recurse(expr.operands[i], filter, is_left)
        
        elif type(expr) in (value_t, regloc_t, var_t, arg_t):
            pass
            
        else:
            #~ print repr(expr)
            raise RuntimeError('cannot iterate over expression of type %s' % (type(expr), ))
        
        expr = filter(expr, is_left)
        return expr
    
    def combine_block_tail(self, block, container):
        """ combine goto's with their destination, if the destination meet some criterias """
        
        combined = False
        while len(container) > 0:
            
            last_stmt = container[-1]
            
            if type(last_stmt) != goto_t or type(last_stmt.expr) != value_t:
                break
            
            dst_ea = last_stmt.expr.value
            dst_block = self.blocks[dst_ea]
            
            #~ if len(dst_block.jump_to) == 1 and len(dst_block.jump_from) == 1:
            
            # check if there is only one jump destination, with the exception of jumps to itself (loops)
            jump_src = [src for src in dst_block.jump_from]
            #~ print 'src', repr([hex(s.ea) for s in jump_src])
            if len(jump_src) == 1:
                #~ print 'combine block', hex(block.ea), 'with', hex(dst_block.ea)
                
                container.pop()
                container.extend(dst_block.container[:])
                block.jump_to += dst_block.jump_to
                #~ block.jump_from += dst_block.jump_from
                
                if dst_block in block.jump_to:
                    block.jump_to.remove(dst_block)
                if block in dst_block.jump_from:
                    dst_block.jump_from.remove(block)
                
                for to_block in dst_block.jump_to[:]:
                    if dst_block in to_block.jump_from:
                        to_block.jump_from.remove(dst_block)
                    to_block.jump_from.append(block)
                
                block.items += dst_block.items
                
                combined = True
            else:
                break
        
        return combined
    
    def combine_else_tails(self, block, container):
        """ if a block contains an if_t whose then-side ends with the same 
            goto_t as the block, itself, then merge all expressions at the 
            end of the block into the else-side of the if_t. """
        
        combined = False
        for i in range(len(container)):
            expr = container[i]
            if not (type(expr) == if_t and len(expr.then_expr) >= 1):
                continue
            
            if not (type(container[-1]) == goto_t and type(expr.then_expr[-1]) == goto_t):
                continue
                
            if not (container[-1] == expr.then_expr[-1]):
                continue
            
            goto = expr.then_expr.pop(-1)
            dstblock = self.blocks[goto.expr.value]
            
            block.jump_to.remove(dstblock)
            
            if block in dstblock.jump_from:
                dstblock.jump_from.remove(block)
            
            stmts = container[i+1:-1]
            container[i+1:-1] = []
            expr.else_expr = container_t(stmts)
            
            combined = True
            break
        
        return combined
    
    def combine_increments(self, block, container):
        """ process if_t """
        combined = False
        
        for stmt in container:
            if type(stmt) == statement_t and type(stmt.expr) == assign_t and \
                    type(stmt.expr.op2) == add_t and (stmt.expr.op1 == stmt.expr.op2.op1 and stmt.expr.op2.op2 == value_t(1)):
                
                stmt.expr = inc_t(stmt.expr.op1.copy())
        
        return
    
    def combine_ifs(self, block, container):
        """ process if_t """
        combined = False
        
        for stmt in container:
            if type(stmt) == if_t:
                #~ print 'then', repr(stmt.then_expr)
                combined = combined or self.combine_single_block(block, stmt.then_expr)
                if stmt.else_expr:
                    combined = combined or self.combine_single_block(block, stmt.else_expr)
            
            # invert then and else side if then-side is empty
            if type(stmt) == if_t and stmt.else_expr is not None and len(stmt.then_expr) == 0:
                stmt.then_expr = stmt.else_expr
                stmt.expr = not_t(stmt.expr)
                stmt.else_expr = None
                
                self.simplify_statement(stmt)
                
                combined = True
        
        # combine block tail into the else-side if the goto at the end of if_t has the same
        # destination as the goto at the end of the block.
        combined = combined or self.combine_else_tails(block, container)
        
        return combined
    
    def combine_single_block(self, block, container):
        """ process all possible combinations for a single block of expressions """
        
        combined_any = False
        while True:
            combined = False
            combined = self.combine_block_tail(block, container)
            combined = combined or self.combine_ifs(block, container)
            combined = combined or self.combine_increments(block, container)
            combined_any = combined_any or combined
            if not combined:
                break
        
        return combined_any
    
    def combine_while(self, block):
        """ process while_t """
        
        first = block.container[0]
        
        if type(first) != if_t:
            return False
        
        if first.else_expr:
            return False
        
        goto = first.then_expr[-1]
        
        if type(goto) != goto_t:
            return False
        
        if goto.expr.value != block.ea:
            return False
        
        # we have an if_t with a goto as last statement which leads back to this block.
        
        # remove goto
        first.then_expr.pop(-1)
        # remove first statement (the if_t)
        block.container.remove(first)
        
        newstmt = while_t(first.expr, first.then_expr)
        block.container.insert(0, newstmt)
        
        block.jump_from.remove(block)
        block.jump_to.remove(block)
        
        return True
    
    def combine_do_while(self, block):
        """ process do_while_t """
        
        
        for i in range(len(block.container)):
            
            stmt = block.container[i]
            
            if type(stmt) != if_t:
                continue
            
            if stmt.else_expr:
                continue
            
            if len(stmt.then_expr) != 1 or type(stmt.then_expr[0]) != goto_t:
                continue
            
            goto = stmt.then_expr[0]
            
            if goto.expr.value != block.ea:
                return False
            
            # we have an if_t with a goto as the only statement which leads back to this block.
            
            # remove goto
            stmt.then_expr.pop(0)
            # remove if_t statement
            block.container.remove(stmt)
            
            # make a container out of previous statements
            stmts = block.container[:i]
            block.container[:i] = []
            
            # insert new statement into current block.
            newstmt = do_while_t(stmt.expr, container_t(stmts))
            block.container.insert(0, newstmt)
            
            block.jump_from.remove(block)
            block.jump_to.remove(block)
            
            return True
        
        return False
    
    def combine_blocks(self):
        """ process combining of all blocks """
        
        while True:
            combined = False
            for block in self.iterblocks():
                combined = combined or self.combine_single_block(block, block.container)
                combined = combined or self.combine_while(block)
                combined = combined or self.combine_do_while(block)
            if not combined:
                break
        
        return
