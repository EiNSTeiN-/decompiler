import idautils
import idaapi
import idc

try:
    reload(dec_types)
except:
    pass

from statements import *
from expressions import *
from flow import flow_t

import filters.simplify_expressions
import callconv

class tagger():
    
    def __init__(self, flow):
        self.flow = flow
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        self.tagged_pairs = []
        
        self.fct_undefined = []
        
        self.conv = callconv.systemv_x64_abi()
        
        return
    
    def get_defs(self, expr):
        return [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and defreg.is_def]
    
    def get_uses(self, expr):
        return [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and not defreg.is_def]
    
    def get_block_externals(self, block):
        """ return all externals for a single block. at this stage, blocks are very flat, and ifs
        should contain only gotos, so doing this with a simple loop like below should be safe """
        
        externals = []
        context = []
        
        for stmt in block.container.statements:
            
            uses = self.get_uses(stmt.expr)
            for use in uses:
                if use not in context:
                    in_external = False
                    for external, _stmt in externals:
                        if external == use:
                            in_external = True
                            break
                    if not in_external:
                        externals.append((use, stmt))
            
            defs = self.get_defs(stmt.expr)
            for _def in defs:
                context.append(_def)
        
        return externals
    
    def find_call(self, stmt):
        
        if type(stmt.expr) == call_t:
            return stmt.expr
        
        if type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
            return stmt.expr.op2
        
        return
    
    def tag_expression(self, block, container, stmt, expr, context):
        
        if not expr:
            return
        
        call = self.find_call(stmt)
        if call:
            self.conv.process(self.flow, block, stmt, call, context)
        
        defs = [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and defreg.is_def]
        uses = [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and not defreg.is_def]
        
        for use in uses:
            old_def = context.get_definition(use)
            if old_def:
                reg, _, _ = old_def
                use.index = reg.index
        
        for _def in defs:
            pos = container.index(stmt)
            context.new_definition(_def, container, stmt)
        
        return
    
    def tag_statement(self, block, container, stmt, context):
        
        if type(stmt) == if_t:
            self.tag_expression(block, container, stmt, stmt.expr, context)
            
            self.tag_container(block, stmt.then_expr, context)
            
            assert stmt.else_expr is None, 'at this stage there should be no else-branch'
        
        elif type(stmt) == goto_t:
            ea = stmt.expr.value
            to_block = self.flow.blocks[ea]
            self.tag_block(block, to_block, context.copy())
        
        elif type(stmt) in (statement_t, return_t):
            self.tag_expression(block, container, stmt, stmt.expr, context)
        
        else:
            raise RuntimeError('unknown statement type: %s' % (repr(stmt), ))
        
        return
    
    def tag_container(self, block, container, context):
        
        for stmt in container[:]:
            self.tag_statement(block, container, stmt, context)
            
        return
    
    def tag_block(self, parent, block, context):
        
        #~ print 'exploring %x from %s' % (block.ea, hex(parent.ea) if parent else '(entry)')
        
        externals = [(reg, stmt) for reg, stmt in self.get_block_externals(block)]
        #~ print 'externals are', repr([str(e) for e, _ in externals])
        
        for external, stmt in externals:
            # add assignation to this instance of the register in any earlier block that affects
            # this register in the current contect.
            _earlier_def = context.get_definition(external)
            
            # each register which is used in a block without being first defined
            # becomes its own definition, therefore we need to introduce these 
            # as definitions into the current context.
            if external.index is None:
                self.fct_undefined.append(external)
                context.new_definition(external, block.container, stmt)
            
            if _earlier_def:
                _reg, _container, _stmt = _earlier_def
                
                # prevent inserting the same assignation multiple times
                pair = (external, _reg)
                if pair in self.tagged_pairs:
                    continue
                self.tagged_pairs.append(pair)
                
                # insert the new assignation
                expr = assign_t(external.copy(), _reg.copy())
                expr.op1.is_def = True
                _container.insert(_container.index(_stmt)+1, statement_t(expr)) # insert just before goto
        
        if block in self.done_blocks:
            #~ print 'already done %x' % block.ea
            return
        
        self.done_blocks.append(block)
        
        self.tag_container(block, block.container, context.copy())
        
        #~ print 'exploring %x done' % block.ea
        
        return
    
    def tag_all(self):
        
        self.done_blocks = []
        
        context = tag_context_t()
        self.tag_block(None, self.flow.entry_block, context)
        
        return

class tag_context_t(object):
    
    index = 0
    
    def __init__(self):
        
        self.map = []
        
        return
    
    def copy(self):
        new = tag_context_t()
        new.map = self.map[:]
        return new
    
    def get_definition(self, reg):
        """ get an earlier definition of 'reg'. """
        
        for _reg, _where, _pos in self.map:
            if _reg.which == reg.which:
                return _reg, _where, _pos
        
        return
    
    def remove_definition(self, reg):
        
        for _reg, _where, _pos in self.map:
            if _reg.which == reg.which:
                self.map.remove((_reg, _where, _pos))
        
        return
    
    def new_definition(self, reg, container, pos):
        
        for _reg, _where, _pos in self.map:
            if _reg.which == reg.which:
                self.map.remove((_reg, _where, _pos))
        
        reg.index = tag_context_t.index
        tag_context_t.index += 1
        
        self.map.append((reg, container, pos))
        
        return

class instance_t(object):
    
    def __init__(self, block, stmt, reg):
        
        self.block = block
        self.stmt = stmt
        self.reg = reg
        
        return
    
    def __eq__(self, other):
        return other.block == self.block and other.stmt == self.stmt and \
                other.reg == self.reg

class chain_t(object):
    """ this object holds instances of a register. those instances can be 
    definition statements or uses. a register is 'defined' when it appears
    on the left side of an assing_t expression, such as 'eax = 0' except
    if it is part of another construct, such that '*(eax) = 0' does not
    constitute a definition of eax but a use of eax.
    """
    
    def __init__(self, defreg):
        
        self.defreg = defreg
        self.instances = []
        
        return
    
    def __repr__(self):
        s = '<chain %s: %s>' % (str(self.defreg), repr([str(i.stmt) for i in self.instances]))
        return s
    
    def new_instance(self, instance):
        if instance in self.instances:
            return
        self.instances.append(instance)
        return
    
    @property
    def defines(self):
        for instance in self.instances:
            if instance.reg.is_def:
                yield instance
        return
    
    @property
    def uses(self):
        for instance in self.instances:
            if not instance.reg.is_def:
                yield instance
        return
    
    def replace_operands(self, useinstance, expr, value):
        
        if expr == self.defreg:
            if useinstance in self.instances:
                self.instances.remove(useinstance)
            return value.copy()
        
        if isinstance(expr, expr_t):
            for i in range(len(expr.operands)):
                expr.operands[i] = self.replace_operands(useinstance, expr.operands[i], value)
                expr.operands[i] = filters.simplify_expressions.run(expr.operands[i])
        
        expr = filters.simplify_expressions.run(expr)
        return expr
    
    def propagate(self):
        """ take all uses and replace them by the right side of the definition.
        returns True if the propagation was successful. """
        
        #~ print 'foo', repr(self)
        
        if len(list(self.uses)) == 0 and len(list(self.defines)) == 1:
            _def = list(self.defines)[0]
            if _def.reg.is_stackreg:
                _def.stmt.container.remove(_def.stmt)
                return True
        
        # prevent removing anything without uses during propagation. we'll do it later.
        if len(list(self.uses)) == 0:
            return False
        
        defines = list(self.defines)
        if len(defines) != 1:
            # cannot propagate if there is not exactly one definition for this chain
            return False
        
        #~ print 'foo', str(defines[0].reg)
        
        instance = defines[0]
        stmt = instance.stmt
        if type(stmt.expr) != assign_t:
            return False
        
        value = stmt.expr.op2
        
        # prevent multiplying function calls.
        if type(value) == call_t: # and len(list(self.uses)) > 1:
            return False
        
        for useinstance in list(self.uses):
            _stmt = useinstance.stmt
            _stmt.expr = self.replace_operands(useinstance, _stmt.expr, value)
            
            # handle special case where statement is simplified into itself
            if type(_stmt.expr) == assign_t and _stmt.expr.op1 == _stmt.expr.op2:
                _stmt.container.remove(_stmt)
            #~ print 'foo', str(_stmt)
        
        # only remove original statement now iif the value was a call
        if len(list(self.uses)) == 0:
            stmt.container.remove(stmt)
        
        return True

class flow_iterator(object):
    """ Helper class for iterating a flow_t object.
    
    The following callbacks can be used:
        block_iterator(block_t)
        statement_iterator(block_t, statement_t)
        expression_iterator(block_t, statement_t, expr_t)
    
    The expression_iterator callback is expected to return the same expr_t
    passed as parameter, or a new one meant to replace the old one.
    """
    
    def __init__(self, flow, **kwargs):
        self.flow = flow
        
        self.block_iterator = kwargs.get('block_iterator')
        self.statement_iterator = kwargs.get('statement_iterator')
        self.expression_iterator = kwargs.get('expression_iterator')
        
        return
    
    def do_expression(self, block, stmt, expr):
        
        newexpr = self.expression_iterator(block, stmt, expr)
        if newexpr is not None:
            return newexpr
        
        if not expr:
            return expr
        
        if isinstance(expr, expr_t):
            for i in range(len(expr.operands)):
                expr.operands[i] = self.do_expression(block, stmt, expr.operands[i])
        
        return expr
    
    def do_statement(self, block, stmt):
        
        if self.statement_iterator:
            self.statement_iterator(block, stmt)
        
        for _stmt in list(stmt.statements):
            self.do_statement(block, _stmt)
        
        if type(stmt) == goto_t and type(stmt.expr) == value_t:
            ea = stmt.expr.value
            block = self.flow.blocks[ea]
            self.do_block(block)
        else:
            
            if self.expression_iterator:
                stmt.expr = self.do_expression(block, stmt, stmt.expr)
        
        return
    
    def do_block(self, block):
        
        if block in self.done_blocks:
            return
        
        self.done_blocks.append(block)
        
        if self.block_iterator:
            self.block_iterator(block)
        
        for stmt in block.container.statements:
            self.do_statement(block, stmt)
        
        return
    
    def do(self):
        
        self.done_blocks = []
        block = self.flow.entry_block
        self.do_block(block)
        
        return

class simplifier(object):
    
    def __init__(self, flow):
        
        self.flow = flow
        self.done_blocks = []
        
        self.reg_arguments = {}
        self.reg_variables = {}
        self.stack_variables = {}
        self.varn = 0
        self.argn = 0
        
        return
    
    def find_reg_chain(self, chains, reg):
        
        for chain in chains:
            if chain.defreg == reg:
                return chain
        
        return
    
    def get_statement_chains(self, block, stmt, chains):
        
        for _stmt in stmt.statements:
            self.get_statement_chains(block, _stmt, chains)
        
        if type(stmt) == goto_t and type(stmt.expr) == value_t:
            
            ea = stmt.expr.value
            _block = self.flow.blocks[ea]
            
            self.get_block_chains(_block, chains)
            return
        
        regs = [reg for reg in stmt.expr.iteroperands() if type(reg) == regloc_t]
        
        for reg in regs:
            chain = self.find_reg_chain(chains, reg)
            if not chain:
                chain = chain_t(reg)
                chains.append(chain)
            instance = instance_t(block, stmt, reg)
            chain.new_instance(instance)
        
        return
    
    def get_block_chains(self, block, chains):
        
        if block in self.done_blocks:
            #~ print 'already done block:', hex(block.ea)
            return
        
        self.done_blocks.append(block)
        
        for stmt in list(block.container.statements):
            self.get_statement_chains(block, stmt, chains)
        
        return
    
    def get_chains(self):
        
        self.done_blocks = []
        chains = []
        self.get_block_chains(self.flow.entry_block, chains)
        
        return chains
    
    def tag(self):
        t = tagger(self.flow)
        self.chains = t.tag_all()
        self.fct_arguments = t.fct_undefined[:]
        return
    
    def propagate_expressions(self):
        
        while True:
            redo = False
            
            chains = self.get_chains()
            
            for chain in chains:
                redo = chain.propagate() or redo
            
            if not redo:
                break
        
        return
    
    def is_stackvar(self, expr):
        return (type(expr) == regloc_t and expr.which == self.flow.stackreg.which) or \
                ((type(expr) == sub_t and type(expr.op1) == regloc_t and \
                expr.op1.which == self.flow.stackreg.which and type(expr.op2) == value_t))
    
    def stack_variable(self, expr):
        
        assert self.is_stackvar(expr)
        
        if type(expr) == regloc_t and expr.which == self.flow.stackreg.which:
            index = 0
        else:
            index = -(expr.op2.value)
        
        if index in self.stack_variables:
            return self.stack_variables[index].copy()
        
        var = var_t(expr.copy())
        var.name = 'v%u' % (self.varn, )
        self.varn += 1
        
        self.stack_variables[index] = var
        
        return var
    
    def reg_variable(self, expr):
        
        assert type(expr) == regloc_t
        
        for reg in self.reg_variables:
            if reg == expr:
                return self.reg_variables[reg]
        
        var = var_t(expr)
        self.reg_variables[expr] = var
        
        var.name = 'v%u' % (self.varn, )
        self.varn += 1
        
        return var
    
    def reg_argument(self, expr):
        
        assert type(expr) == regloc_t
        
        for reg in self.reg_arguments:
            if reg == expr:
                return self.reg_arguments[reg]
        
        arg = arg_t(expr)
        self.reg_arguments[expr] = arg
        
        arg.name = 'a%u' % (self.argn, )
        self.argn += 1
        
        return arg
    
    def rename_variables_cb(self, block, stmt, expr):
        
        if not expr:
            return
        
        # stack variable value
        if type(expr) == deref_t and self.is_stackvar(expr.op):
            var = self.stack_variable(expr.op)
            return var
        
        # stack variable address
        if self.is_stackvar(expr):
            var = self.stack_variable(expr)
            return address_t(var)
        
        if type(expr) == regloc_t and expr in self.fct_arguments:
            arg = self.reg_argument(expr)
            return arg
        
        if type(expr) == regloc_t:
            var = self.reg_variable(expr)
            return var
        
        return
    
    def rename_variables(self):
        
        iter = flow_iterator(self.flow, expression_iterator = self.rename_variables_cb)
        iter.do()
        
        return

class argument_collector(object):
    
    def __init__(self, flow, conv):
        self.flow = flow
        self.conv = conv
        
        self.context = []
        
        return
    
    def remove_context(self, searchreg):
        
        for reg, value in self.context:
            if type(searchreg) == regloc_t and type(reg) == regloc_t and \
                reg.which == searchreg.which:
                self.context.remove((reg, value))
                break
            if searchreg == reg:
                self.context.remove((reg, value))
                break
        
        return
    
    def context_add(self, assignee, value):
        
        self.remove_context(assignee)
        self.context.append((assignee, value))
        
        return
    
    def get_context(self, searchreg):
        
        for reg, value in reversed(self.context):
            
            if type(searchreg) == regloc_t and type(reg) == regloc_t and \
                reg.which == searchreg.which:
                return reg, value
            
            if searchreg == reg:
                return reg, value
        
        return
    
    def find_call(self, stmt):
        
        if type(stmt.expr) == call_t:
            return stmt.expr
        
        if type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
            return stmt.expr.op2
        
        return
    
    def collect_call_arguments_cb(self, block, stmt):
        
        call = self.find_call(stmt)
        if call:
            self.conv.process(self.flow, block, stmt, call, self)
        
        if type(stmt.expr) != assign_t:
            return
        
        defs = [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and defreg.is_def]
        uses = [defreg for defreg in expr.iteroperands() if type(defreg) is regloc_t and not defreg.is_def]
        
        assignee = stmt.expr.op1
        value = stmt.expr.op2
        
        self.context_add(assignee, value)
        
        return
    
    def collect_call_arguments(self):
        
        iter = flow_iterator(self.flow, statement_iterator = self.collect_call_arguments_cb)
        iter.do()
        
        return

print 'here:', idc.here()
func = idaapi.get_func(idc.here())

f = flow_t(func.startEA)
f.prepare_blocks()
s = simplifier(f)

print '----1----'
print str(f)
print '----1----'

# tag all register so that each instance of a register
# can be uniquely identified.
s.tag()

# after registers are tagged, we can replace their uses by their definitions.
s.propagate_expressions()

# take function calls and add live registers to their argument list
# in accordance with the calling convention. after this, propagate again.
#~ arg = argument_collector(f, callconv.systemv_x64_abi())
#~ arg.collect_call_arguments()
#~ s.propagate_expressions()

# rename variables to pretty names
s.rename_variables()

# after everything is propagated, we can combine blocks!
f.combine_blocks()

print '----2----'
print str(f)
print '----2----'

