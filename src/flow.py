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
        
        #~ self.branch_expr = None
        
        #~ self.return_expr = None
        self.falls_into = None
        
        return
    
    def __repr__(self):
        return '<flowblock %s>' % (repr(self.container), )
    
    def __str__(self):
        return str(self.container)

class flow_t(object):
    
    def __init__(self, entry_ea, arch, follow_calls=True):
        
        self.entry_ea = entry_ea
        self.follow_calls = follow_calls
        self.arch = arch
        
        self.func_items = list(idautils.FuncItems(self.entry_ea))
        
        self.return_blocks = []
        
        self.entry_block = None
        self.blocks = {}
        
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
    
    def get_block(self, addr):
        
        if type(addr) == goto_t:
            
            if type(addr.expr) != value_t:
                raise RuntimeError('goto_t.expr is not value_t')
            
            ea = addr.expr.value
        
        elif type(addr) == value_t:
            ea = addr.value
        
        elif type(addr) in (long, int):
            ea = addr
        
        if ea not in self.blocks:
            return None
        
        return self.blocks[ea]
    
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
        """ find each point in the function which is the 
        destination of a jump (conditional or not).
        
        jump destinations are the points that delimit new
        blocks. """
        
        for item in idautils.FuncItems(self.entry_ea):
            
            insn = idautils.DecodeInstruction(item)
            mnem = idc.GetMnem(item)
            
            if self.arch.has_jump(item):
                
                for ea in self.arch.jump_branches(item):
                    yield ea
        
        return
    
    def find_control_flow(self):
        
        # find all jump targets
        jump_targets = list(set(self.jump_targets()))
        
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
                #~ assert insn.size > 0, '%x: 
                
                if self.arch.is_return(ea):
                    
                    self.return_blocks.append(block)
                    break
                
                elif self.arch.has_jump(ea):
                    
                    for ea_to in self.arch.jump_branches(ea):
                        
                        if ea_to not in self.func_items:
                            print '%x: jumped outside of function to %x' % (ea, ea_to, )
                        else:
                            toblock = self.blocks[ea_to]
                            block.jump_to.append(toblock)
                            toblock.jump_from.append(block)
                    
                    break
                
                if self.arch.next_instruction(ea) not in self.func_items:
                    print '%x: jumped outside of function: %x' % (ea, ea + insn.size)
                    break
                
                ea = self.arch.next_instruction(ea)
                
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
    
    def simplify_expressions(self, expr):
        """ combine expressions until it cannot be combined any more. return the new expression. """
        
        return filters.simplify_expressions.run(expr, deep=True)
    
    def simplify_statement(self, stmt):
        """ find any expression present in a statement and simplify them. if the statement
            has other statements nested (as is the case for if-then, while, etc), then 
            sub-statements are also processed. """
        
        # simplify sub-statements
        for _stmt in stmt.statements:
            self.simplify_statement(_stmt)
        
        #~ stmt.expr = self.filter_expression(stmt.expr, self.simplify_expressions)
        stmt.expr = filters.simplify_expressions.run(stmt.expr, deep=True)
        
        return stmt
    
    def prepare_statement(self, item):
        """ always return a statement from an expression or a statement. """
        
        if isinstance(item, statement_t):
            stmt = item
        elif isinstance(item, expr_t):
            stmt = statement_t(item)
        else:
            raise RuntimeError("don't know how to make a statement with %s" % (repr(item), ))
        
        return stmt
    
    def prepare_blocks(self):
        """ put blocks in something close to ssa form. """
        
        for block in self.iterblocks():
            
            # for all item in the block, process each statement.
            for item in block.items:
                for expr in self.arch.generate_statements(item):
                    
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
        
        elif type(expr) in (value_t, flagloc_t, regloc_t, var_t, arg_t):
            pass
        
        else:
            #~ print repr(expr)
            raise RuntimeError('cannot iterate over expression of type %s' % (type(expr), ))
        
        expr = filter(expr)
        return expr
    
    def combine_blocks(self):
        
        filters.controlflow.run(self)
        
        return
