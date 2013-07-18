""" Transform the program flow in SSA form.

"""

from statements import *
from expressions import *

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
        
        for _reg, _stmt in self.map:
            if _reg.no_index_eq(reg):
                return _reg, _stmt
        
        return
    
    def remove_definition(self, reg):
        
        for _reg, _stmt in self.map:
            if _reg.no_index_eq(reg):
                self.map.remove((_reg, _stmt))
        
        return
    
    def new_definition(self, reg, stmt):
        
        for _reg, _stmt in self.map:
            if _reg.no_index_eq(reg):
                self.map.remove((_reg, _stmt))
        
        reg.index = tag_context_t.index
        tag_context_t.index += 1
        
        self.map.append((reg, stmt))
        
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
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        self.tagged_pairs = []
        
        self.fct_arguments = []
        
        return
    
    def get_defs(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and defreg.is_def]
    
    def get_uses(self, expr):
        return [defreg for defreg in expr.iteroperands() if isinstance(defreg, assignable_t) and not defreg.is_def]
    
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
    
    #~ def find_call(self, stmt):
        
        #~ if type(stmt.expr) == call_t:
            #~ return stmt.expr
        
        #~ if type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
            #~ return stmt.expr.op2
        
        #~ return
    
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
        
        if type(stmt) == if_t:
            self.tag_expression(block, container, stmt, stmt.expr, context)
            
            self.tag_container(block, stmt.then_expr, context)
            
            assert stmt.else_expr is None, 'at this stage there should be no else-branch'
        
        elif type(stmt) == goto_t:
            ea = stmt.expr.value
            to_block = self.flow.blocks[ea]
            self.tag_block(block, to_block, context.copy())
        
        elif type(stmt) in (statement_t, return_t, jmpout_t):
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
                context.new_definition(external, stmt)
            
            if not _earlier_def:
                continue
            
            _reg, _stmt = _earlier_def
            
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
                _stmt.container.insert(_stmt.index(), statement_t(expr))
            else:
                # insert the new assignation
                expr = assign_t(external.copy(), _reg.copy())
                _stmt.container.insert(_stmt.index()+1, statement_t(expr))
        
        if block in self.done_blocks:
            return
        
        self.done_blocks.append(block)
        
        self.tag_container(block, block.container, context.copy())
        
        return
    
    def tag(self):
        
        self.done_blocks = []
        
        context = tag_context_t()
        self.tag_block(None, self.flow.entry_block, context)
        
        return
