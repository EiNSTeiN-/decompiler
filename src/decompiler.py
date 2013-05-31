import idautils
import idaapi
import idc

from statements import *
from expressions import *
from flow import flow_t

import filters.simplify_expressions
import callconv
from arch.intel import arch_intel

class tag_context_t(object):
    """ holds a list of registers that are live while the tagger runs """
    
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

class tagger():
    """ this object follows all paths in the function and tags registers """
    
    def __init__(self, flow):
        self.flow = flow
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        self.tagged_pairs = []
        
        self.fct_arguments = []
        
        self.conv = callconv.systemv_x64_abi()
        
        return
    
    def get_defs(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, regloc_t) and defreg.is_def]
    
    def get_uses(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, regloc_t) and not defreg.is_def]
    
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
        
        defs = self.get_defs(expr)
        uses = self.get_uses(expr)
        
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
        
        externals = [(reg, stmt) for reg, stmt in self.get_block_externals(block)]
        
        for external, stmt in externals:
            # add assignation to this instance of the register in any earlier block that affects
            # this register in the current contect.
            _earlier_def = context.get_definition(external)
            
            # each register which is used in a block without being first defined
            # becomes its own definition, therefore we need to introduce these 
            # as definitions into the current context.
            if external.index is None:
                self.fct_arguments.append(external)
                context.new_definition(external, block.container, stmt)
            
            if not _earlier_def:
                continue
            
            _reg, _container, _stmt = _earlier_def
            
            if _reg == external:
                continue
            
            # prevent inserting the same assignation multiple times
            pair = (external, _reg)
            if pair in self.tagged_pairs:
                continue
            self.tagged_pairs.append(pair)
            
            if type(_stmt) == if_t:
                # the definition is part of the expression in a if_t. this is a special case where
                # we insert the assignment before the if_t.
                expr = assign_t(external.copy(), _reg.copy())
                _container.insert(_container.index(_stmt), statement_t(expr))
            else:
                # insert the new assignation
                expr = assign_t(external.copy(), _reg.copy())
                _container.insert(_container.index(_stmt)+1, statement_t(expr))
        
        if block in self.done_blocks:
            return
        
        self.done_blocks.append(block)
        
        self.tag_container(block, block.container, context.copy())
        
        return
    
    def tag_all(self):
        
        self.done_blocks = []
        
        context = tag_context_t()
        self.tag_block(None, self.flow.entry_block, context)
        
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
    definitions or uses. a register is 'defined' when it appears
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
        return [instance for instance in self.instances if instance.reg.is_def]
    
    @property
    def uses(self):
        return [instance for instance in self.instances if not instance.reg.is_def]
    
    def replace_operands(self, useinstance, expr, value):
        
        if expr == self.defreg:
            if useinstance in self.instances:
                self.instances.remove(useinstance)
            return value.copy()
        
        if isinstance(expr, expr_t):
            for i in range(len(expr)):
                expr[i] = self.replace_operands(useinstance, expr[i], value)
                expr[i] = filters.simplify_expressions.run(expr[i], deep=True)
        
        expr = filters.simplify_expressions.run(expr, deep=True)
        return expr
    
    def all_same_definitions(self):
        """ return True if all definitions of this chain are the exact
            same expression. """
        defines = self.defines
        first = defines[0]
        for define in defines[1:]:
            if define.stmt.expr == first.stmt.expr:
                continue
            return False
        return True
    
    def propagate(self):
        """ take all uses and replace them by the right side of the definition.
        returns True if the propagation was successful. """
        
        if len(self.uses) == 0 and len(self.defines) == 1:
            _def = self.defines[0]
            if _def.reg.is_stackreg:
                _def.stmt.container.remove(_def.stmt)
                return True
        
        if self.defreg.is_stackreg:
            print 'err', repr(self)
        
        # prevent removing anything without uses during propagation. we'll do it later.
        defines = self.defines
        if len(self.uses) == 0 or len(defines) == 0:
            return False
        
        if len(defines) > 1 and not self.all_same_definitions():
            # cannot propagate if there is not exactly one definition for this chain
            return False
        
        instance = defines[0]
        stmt = instance.stmt
        if type(stmt.expr) != assign_t:
            return False
        
        value = stmt.expr.op2
        
        # prevent multiplying function calls.
        if type(value) == call_t: # and len(self.uses) > 1:
            return False
        
        for useinstance in self.uses:
            _stmt = useinstance.stmt
            _stmt.expr = self.replace_operands(useinstance, _stmt.expr, value)
            
            # handle special case where statement is simplified into itself
            if type(_stmt.expr) == assign_t and _stmt.expr.op1 == _stmt.expr.op2:
                _stmt.container.remove(_stmt)
            #~ print 'foo', str(_stmt)
        
        # only remove original statement now iif the value was a call
        if len(self.uses) == 0:
            for define in defines:
                define.stmt.container.remove(define.stmt)
        
        return True

# what are we collecting now
COLLECT_REGISTERS = 1
COLLECT_FLAGS = 2
COLLECT_ARGUMENTS = 4
COLLECT_VARIABLES = 8
COLLECT_ALL = COLLECT_REGISTERS | COLLECT_FLAGS | COLLECT_ARGUMENTS | COLLECT_VARIABLES

class simplifier(object):
    
    def __init__(self, flow, flags):
        
        self.flow = flow
        self.flags = flags
        
        self.done_blocks = []
        
        self.return_chains = {}
        
        return
    
    def should_collect(self, expr):
        if not isinstance(expr, assignable_t):
            return False
        
        if self.flags & COLLECT_REGISTERS and type(expr) == regloc_t:
            return True
        if self.flags & COLLECT_FLAGS and type(expr) == flagloc_t:
            return True
        if self.flags & COLLECT_ARGUMENTS and type(expr) == arg_t:
            return True
        if self.flags & COLLECT_VARIABLES and type(expr) == var_t:
            return True
        
        return False
    
    def find_reg_chain(self, chains, reg):
        """ find the chain that matches this exact register. """
        
        for chain in chains:
            if chain.defreg == reg:
                return chain
        
        return
    
    def get_statement_chains(self, block, stmt, chains):
        """ for a statement, get all registers that appear in it. """
        
        for _stmt in stmt.statements:
            self.get_statement_chains(block, _stmt, chains)
        
        if type(stmt) == goto_t and type(stmt.expr) == value_t:
            
            ea = stmt.expr.value
            _block = self.flow.blocks[ea]
            
            self.get_block_chains(_block, chains)
            return
        
        regs = [reg for reg in stmt.expr.iteroperands() if self.should_collect(reg)]
        
        for reg in regs:
            chain = self.find_reg_chain(chains, reg)
            if not chain:
                chain = chain_t(reg)
                chains.append(chain)
            instance = instance_t(block, stmt, reg)
            chain.new_instance(instance)
        
        if type(stmt) == return_t:
            self.return_chains[block] = chains[:]
        
        return
    
    def get_block_chains(self, block, chains):
        
        if block in self.done_blocks:
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
    
    def propagate_expressions(self):
        """ for each chain we can find, replace its uses by its definitions """
        
        while True:
            redo = False
            
            chains = self.get_chains()
            
            for chain in chains:
                redo = chain.propagate() or redo
            
            if not redo:
                break
        
        return
    
    def remove_unused_definitions(self):
        """ remove definitions that don't have any uses """
        
        chains = self.get_chains()
        for chain in chains:
            
            if len(chain.uses) > 0:
                continue
            
            for instance in chain.defines:
                instance.stmt.container.remove(instance.stmt)
        
        return
    
    def process_restores(self):
        """ we try to find chains for any 'x' that has a single 
        definition of the style 'x = y' and where all uses are 
        of the style 'y = x' and y is either a stack location 
        or the same register (not taking the index into account).
        
        one further condition is that all definitions of 'y' have
        no uses and be live at the return statement.
        """
        
        #~ print 'at restore'
        chains = self.get_chains()
        
        restored_regs = []
        #~ print repr(chains)
        
        for chain in chains:
            defs = chain.defines
            uses = chain.uses
            
            if len(defs) != 1 or len(uses) == 0:
                continue
            
            defstmt = defs[0].stmt
            if type(defstmt.expr) != assign_t:
                continue
            
            def_chain = self.find_reg_chain(chains, defstmt.expr.op2)
            if not def_chain or len(def_chain.uses) != 1:
                continue
            
            defreg = def_chain.defreg
            
            all_restored = True
            
            for use in uses:
                
                if type(use.stmt.expr) != assign_t:
                    all_restored = False
                    break
                
                usechain = self.find_reg_chain(chains, use.stmt.expr.op1)
                if not usechain or len(usechain.defines) != 1:
                    all_restored = False
                    break
                
                reg = usechain.defines[0].reg
                if type(defreg) != type(reg):
                    all_restored = False
                    break
                
                if type(reg) == regloc_t and (reg.which != defreg.which):
                    all_restored = False
                    break
                    
                if type(reg) != regloc_t and (reg != defreg):
                    all_restored = False
                    break
            
            if all_restored:
                print 'restored', str(defreg)
                
                # pop all statements in which the restored location appears
                for inst in chain.instances:
                    inst.stmt.container.remove(inst.stmt)
                
                reg = defreg.copy()
                reg.index = None
                restored_regs.append(reg)
        
        print 'restored regs', repr([str(r) for r in restored_regs])
        
        return restored_regs

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
            for i in range(len(expr)):
                expr[i] = self.do_expression(block, stmt, expr[i])
        
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

RENAME_STACK_LOCATIONS = 1
RENAME_REGISTERS = 2

class renamer(object):
    """ takes care of renaming variables. stack location and registers 
    are wrapped in var_t and arg_t if they are respectively local variables 
    or function arguments.
    """
    
    varn = 0
    argn = 0
    
    def __init__(self, flow, flags):
        self.flow = flow
        self.flags = flags
        
        self.reg_arguments = {}
        self.reg_variables = {}
        #~ self.stack_arguments = {}
        self.stack_variables = {}
        
        return
    
    def is_stackreg(self, reg):
        return reg.which == self.flow.arch.stackreg.which
    
    def is_stackvar(self, expr):
        return (type(expr) == regloc_t and self.is_stackreg(expr)) or \
                ((type(expr) == sub_t and type(expr.op1) == regloc_t and \
                self.is_stackreg(expr.op1) and type(expr.op2) == value_t))
    
    def stack_variable(self, expr):
        
        assert self.is_stackvar(expr)
        
        if type(expr) == regloc_t and self.is_stackreg(expr):
            index = 0
        else:
            index = -(expr.op2.value)
        
        if index in self.stack_variables:
            return self.stack_variables[index].copy()
        
        var = var_t(expr.copy())
        var.name = 's%u' % (renamer.varn, )
        renamer.varn += 1
        
        self.stack_variables[index] = var
        
        return var
    
    def reg_variable(self, expr):
        
        assert type(expr) == regloc_t
        
        for reg in self.reg_variables:
            if reg == expr:
                return self.reg_variables[reg]
        
        var = var_t(expr)
        self.reg_variables[expr] = var
        
        var.name = 'v%u' % (renamer.varn, )
        renamer.varn += 1
        
        return var
    
    def reg_argument(self, expr):
        
        assert type(expr) == regloc_t
        
        for reg in self.reg_arguments:
            if reg == expr:
                return self.reg_arguments[reg]
        
        arg = arg_t(expr)
        self.reg_arguments[expr] = arg
        
        arg.name = 'a%u' % (renamer.argn, )
        renamer.argn += 1
        
        return arg
    
    def rename_variables_callback(self, block, stmt, expr):
        
        if self.flags & RENAME_STACK_LOCATIONS:
            # stack variable value
            if type(expr) == deref_t and self.is_stackvar(expr.op):
                var = self.stack_variable(expr.op)
                return var
        
            # stack variable address
            if self.is_stackvar(expr):
                var = self.stack_variable(expr)
                return address_t(var)
        
        if self.flags & RENAME_REGISTERS:
            if type(expr) == regloc_t and expr in self.fct_arguments:
                arg = self.reg_argument(expr)
                return arg
            
            if type(expr) == regloc_t:
                var = self.reg_variable(expr)
                return var
        
        return
    
    def wrap_variables(self):
        iter = flow_iterator(self.flow, expression_iterator = self.rename_variables_callback)
        iter.do()
        return

print 'here:', idc.here()
func = idaapi.get_func(idc.here())

arch = arch_intel()
f = flow_t(func.startEA, arch)
f.prepare_blocks()

print '----1----'
print str(f)
print '----1----'

# tag all registers so that each instance of a register can be uniquely identified.
# during this process we also take care of matching registers to their respective 
# function calls.
t = tagger(f)
t.tag_all()

# this removes special flags definitions that do not have uses.
s = simplifier(f, COLLECT_FLAGS)
s.remove_unused_definitions()

# after registers are tagged, we can replace their uses by their definitions. this takes 
# care of eliminating any instances of 'esp'.
s = simplifier(f, COLLECT_FLAGS | COLLECT_REGISTERS)
s.propagate_expressions()

# rename stack variables to differenciate them from other dereferences.
r = renamer(f, RENAME_STACK_LOCATIONS)
r.wrap_variables()

# eliminate restored registers. during this pass, the simplifier also collects 
# stack variables.
s = simplifier(f, COLLECT_REGISTERS | COLLECT_VARIABLES)
s.process_restores()
s.remove_unused_definitions() # ONLY after processing restores can we do this

# rename registers to pretty names.
r = renamer(f, RENAME_REGISTERS)
r.fct_arguments = t.fct_arguments
r.wrap_variables()

# eliminate everything that is not used at this point.


# after everything is propagated, we can combine blocks!
f.combine_blocks()

print '----2----'
print str(f)
print '----2----'

"""
TODO:
- simplify foo=call() into just 'call()' if 'foo' is an unused local variable.

"""
