""" Transform the program flow in SSA form.

"""

from statements import *
from expressions import *

class ssa_context_t(object):
    """ holds a list of registers that are live while the tagger runs """
    
    index = 0
    
    def __init__(self):
        
        self.map = []
        
        return
    
    def copy(self):
        new = ssa_context_t()
        new.map = self.map[:]
        return new
    
    def get_definition(self, reg):
        """ get an earlier definition of 'reg'. """
        
        for _reg, _stmt in self.map:
            if _reg.clean() == reg.clean():
                return _reg, _stmt
        
        return
    
    def remove_definition(self, reg):
        
        for _reg, _stmt in self.map:
            if _reg.clean() == reg.clean():
                self.map.remove((_reg, _stmt))
        
        return
    
    def new_definition(self, reg, stmt):
        
        for _reg, _stmt in self.map:
            if _reg.clean() == reg.clean():
                self.map.remove((_reg, _stmt))
        
        for op in reg.iteroperands():
            if isinstance(op, assignable_t) and op.index is None:
                reg.index = ssa_context_t.index
                ssa_context_t.index += 1
        
        self.map.append((reg, stmt))
        
        return

class ssa_block_contexts_t(object):
    """ holds all the different contexts that are possible to get at the entry of a block.
    
    there may be more than one context because of conditional branches (re)defining 
    locations. when analysing a function call to determine its parameters, we can 
    look up which locations are defined in all paths leading to it using this object.
    """
    def __init__(self, block):
        
        # a flowblock_t
        self.block = block
        # all contexts possible at the block entry.
        self.contexts = []
        return
    
    def has_definition(self, loc):
        """ check if `loc` (an assignable_t), has a definition in all possible contexts. """
        
        return

class ssa_tagger_t():
    """ this class follows all paths in the function and tags registers.
    The main task here is to differenciate all memory locations from each
    other, so that each time a register is reassigned it is considered
    different from previous assignments. After doing this, the function flow
    should be in a form somewhat similar to static single assignment
    form, where all locations are defined once and possibly used zero, one or 
    multiple times. What we do differs from SSA form in the following way:
    
    It may happen that a register is defined in multiple paths that merge
    together where it is used without first being reassigned. An example
    of such case:
    
        if(foo)
            eax = 1
        else
            eax = 0
        return eax;
    
    This causes problems because in SSA form, a location must have one
    definition at most. In Van Emmerick's 2007 paper on SSA, this is 
    solved by adding O-functions with which all definitions from previous 
    paths are merged into a single new defintion, like this:
    
        if(foo)
            eax@0 = 1
        else
            eax@1 = 0
        eax@2 = O(eax@0, eax@1)
        return eax@2
    
    The form above respects the SSA form but impacts greatly on code 
    simplicity when it comes to solving O-functions through recursive
    code. What we do is a little bit different, somewhat simpler and
    gives results that are just as 'correct' (or at least they should).
    The tagger will not insert O-functions, but instead, for any register 
    with multiple merging definitions it will insert one intermediate 
    definition in each code path like this:
    
        if(foo)
            eax@0 = 1
            eax@2 = eax@0
        else
            eax@1 = 0
            eax@2 = eax@1
        return eax@2
    
    This makes it very easy to later replace uses of eax@0 and eax@1 
    by their respective definitions, just the way we would for paths 
    without 'merging' registers. This also solves the case of recursive 
    code paths without extra code.
    """
    
    def __init__(self, flow):
        self.flow = flow
        
        # list of `assignable_t` that are _never_ defined anywhere within 
        # the scope of this function.
        self.uninitialized_regs = []
        
        # map of `flowblock_t`: `ssa_block_contexts_t`. this is a copy of the 
        # context at each statement. this is useful when trying to 
        # determine if a register is restored or not, or which locations
        # are defined at a specific location.
        self.block_context = {}
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        # list of `statement_t`
        self.theta_statements = []
        # map of `assignable_t`: `theta_t`
        self.theta_map = {}
        
        return
    
    def get_theta(self, loc):
        
        if loc in self.theta_map:
            return self.theta_map[loc]
        
        return
    
    def create_theta(self, stmt, loc):
        
        t = theta_t()
        newstmt = statement_t(assign_t(loc.copy(), t))
        stmt.container.insert(stmt.index(), newstmt)
        
        self.theta_map[loc] = t
        self.theta_statements.append(newstmt)
        
        return t
    
    def add_theta_loc(self, stmt, loc, prevloc):
        
        t = self.get_theta(loc)
        if not t:
            t = self.create_theta(stmt, loc)
        
        if prevloc in list(t.operands):
            return
        
        t.append(prevloc.copy())
        
        return
    
    def get_defs(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and not isinstance(defreg, deref_t) and defreg.is_def]
    
    def get_uses(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and not isinstance(defreg, deref_t) and not defreg.is_def]
    
    def get_block_externals(self, block):
        """ return all externals for a single block. at this stage, blocks are very flat, and ifs
        should contain only gotos, so doing this with a simple loop like below should be safe """
        
        externals = []
        context = []
        
        for stmt in block.container.statements:
            if stmt in self.theta_statements:
                continue
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
    
    def tag_expression(self, block, container, stmt, expr, context):
        
        if not expr:
            return
        
        defs = self.get_defs(expr)
        uses = self.get_uses(expr)
        
        for use in uses:
            old_def = context.get_definition(use)
            if old_def:
                reg, _ = old_def
                use.index = reg.index
        
        for _def in defs:
            context.new_definition(_def, stmt)
        
        return
    
    def tag_statement(self, block, container, stmt, context):
        
        if stmt in self.theta_statements:
            return
        
        if type(stmt) == branch_t:
            self.tag_expression(block, container, stmt, stmt.expr, context)
            
            to_block = self.flow.get_block(stmt.true)
            if to_block:
                self.tag_block(block, to_block, context.copy())
            
            to_block = self.flow.get_block(stmt.false)
            if to_block:
                self.tag_block(block, to_block, context.copy())
        elif type(stmt) == goto_t:
            to_block = self.flow.get_block(stmt)
            if to_block:
                self.tag_block(block, to_block, context.copy())
        else:
            for expr in stmt.expressions:
                self.tag_expression(block, container, stmt, expr, context)
            
            for container in stmt.containers:
                self.tag_container(block, container, context)
        
        return
    
    def tag_container(self, block, container, context):
        
        for stmt in container[:]:
            self.tag_statement(block, container, stmt, context)
        
        return
    
    def tag_block(self, parent, block, context):
        
        # copy the current context for later use.
        if block not in self.block_context:
            self.block_context[block] = ssa_block_contexts_t(block)
        self.block_context[block].contexts.append(context.copy())
        
        externals = [(reg, stmt) for reg, stmt in self.get_block_externals(block)]
        for external, stmt in externals:
            
            # add assignation to this instance of the register in any earlier block that affects
            # this register in the current contect.
            _earlier_def = context.get_definition(external)
            
            # each register which is used in a block without being first defined
            # becomes its own definition, therefore we need to introduce these 
            # as definitions into the current context.
            if external.index is None:
                context.new_definition(external, stmt)
            
            if type(external) == deref_t:
                continue
            
            if not _earlier_def:
                #~ print 'external', repr(external), external.index
                self.uninitialized_regs.append(external)
                continue
            
            _reg, _stmt = _earlier_def
            
            if _reg == external:
                continue
            
            self.add_theta_loc(stmt, external, _reg)
        
        if block not in self.done_blocks:
        
            self.done_blocks.append(block)
            
            self.tag_container(block, block.container, context.copy())
        
        return
    
    def tag(self):
        
        self.done_blocks = []
        
        context = ssa_context_t()
        self.tag_block(None, self.flow.entry_block, context)
        
        
        
        return
    
    def has_internal_definition(self, stmt, loc):
        """ check if `loc` is defined prior to `stmt` in the same block. 
            Returns a reference to the (properly indexed) definition of `loc`. """
        
        for i in range(stmt.index(), -1, -1):
            _stmt = stmt.container[i]
            if type(_stmt) == statement_t and type(_stmt.expr) == assign_t and \
                    _stmt.expr.op1.clean() == loc.clean():
                return _stmt.expr.op1
        
        return
    
    def has_contextual_definition(self, stmt, loc):
        """ check if `loc` is defined in all paths leading to this block. """
        
        return False
    
    def insert_theta(self, stmt, loc):
        """ insert a theta statement grouping all definitions of `loc` which are present 
            in all paths leading to this block. the new theta statement is inserted just 
            before `stmt`. Returns a reference to the new theta variable decorated with 
            its index. """
        
        return
    


