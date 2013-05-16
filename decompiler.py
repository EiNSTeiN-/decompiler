import idautils
import idaapi
import idc

try:
    reload(dec_types)
except:
    pass

from dec_types import *
from flow import flow_t

class defuse_t():
    
    def __init__(self, definition=None):
        self.defs = []
        self.uses = []
        self.defreg = None
        
        if definition:
            self.defs.append(definition)
            self.defreg = definition.get()
        
        return

class operator_location_t():
    """ wrapper class that holds the location of an operator so it can 
        be easily replaced. """
    
    def __init__(self, container, stmt, expr, index, chain=None):
        self.container = container
        self.stmt = stmt
        self.expr = expr
        self.index = index
        self.chain = chain
        return
    
    def __repr__(self):
        return '<operator location %s>' % (repr(self.get()), )
    
    def copy(self):
        return operator_location_t(self.container, self.stmt, self.expr, \
                self.index, self.chain)
    
    def get(self):
        return self.expr[self.index]
    
    def replace(self, other):
        self.expr[self.index] = other
        return

class statement_location_t():
    """ wrapper class that holds the location of an operator so it can 
        be easily replaced. """
    
    def __init__(self, container, stmt, chain=None):
        self.container = container
        self.stmt = stmt
        self.chain = chain
        return
    
    def __repr__(self):
        return '<statement location %s>' % (repr(self.get()), )
    
    def copy(self):
        return statement_location_t(self.container, self.stmt, self.chain)
    
    def get(self):
        return self.stmt.expr
    
    def replace(self, other):
        self.stmt.expr = other
        return

class chains_t(object):
    
    def __init__(self, chains = None):
        self.chains = chains or []
        #~ self.by_stmt = {}
        self.live = []
        return
    
    def copy(self):
        o = chains_t(self.chains[:])
        #~ o.by_stmt = self.by_stmt.copy()
        o.live = self.live[:]
        return o
    
    def remove(self, loc):
        self.chains.remove(loc)
        
        #~ for stmt in self.by_stmt:
            #~ if loc in self.by_stmt[stmt]:
                #~ self.by_stmt[stmt].remove(loc)
        
        return
    
    def get_stmt(self, stmt):
        _list = {'defines':[], 'uses':[]}
        
        for chain in self.chains:
            for defloc in chain.defs:
                if defloc.stmt == stmt:
                    _list['defines'].append(defloc)
            for useloc in chain.uses:
                if useloc.stmt == stmt:
                    _list['uses'].append(useloc)
        
        if len(_list['defines']) == 0 and len(_list['uses']) == 0:
            return
        
        return _list
    
    def define(self, loc):
        chain = defuse_t(loc)
        
        #~ if loc:
            #~ for _chain in self.chains:
                #~ for _def in _chain.defs:
                    #~ if loc.get() == _def.get() and loc.stmt == _def.stmt:
                        #~ print 're-adding definition!', str(loc.stmt)
                        #~ loc.chain = _chain
                        #~ self.chains.remove(_chain)
                        #~ self.chains.append(_chain)
                        #~ chain.defs.append(loc)
                        #~ return
        
        self.chains.append(chain)
        
        if loc:
            loc.chain = chain
            
            for livechain in self.live:
                for liveloc in livechain.defs:
                    if liveloc.get() == loc.get():
                        self.live.remove(livechain)
                        break
            self.live.append(chain)
            
        return chain
    
    def get_last_definition_chain(self, loc):
        expr = loc.get()
        for chain in reversed(self.chains):
            for _def in chain.defs:
                if _def.get() == expr:
                    return chain
        return
    
    def use(self, loc):
        chain = self.get_last_definition_chain(loc)
        if not chain:
            chain = self.define(None)
        
        # here we make sure that if we are re-adding a register use (for example,
        # due to recursion in the code), that we will merge the old and new chain.
        for _chain in self.chains:
            if _chain == chain:
                continue
            for _use in _chain.uses:
                if loc.get() == _use.get() and loc.stmt == _use.stmt:
                    #~ print 'before', repr([str(o.stmt) for o in chain.defs]), repr([str(o.stmt) for o in _chain.defs])
                    
                    #~ chain.uses.remove(loc)
                    loc.chain = _chain
                    chain.uses.append(_use)
                    
                    for _def in _chain.defs:
                        if _def not in chain.defs:
                            _def.chain = chain
                            chain.defs.append(_def)
                    
                    for _def in _chain.uses:
                        if _def not in chain.uses:
                            _def.chain = chain
                            chain.uses.append(_def)
                    
                    #~ _chain.uses = []
                    #~ _chain.defs = []
                    self.chains.remove(_chain)
                    
                    #~ print 'after', repr([str(o.stmt) for o in chain.defs]), repr([str(o.stmt) for o in _chain.defs])
                    
                    return
    
        loc.chain = chain
        chain.uses.append(loc)
        return

class tagger():
    
    def __init__(self, flow):
        self.flow = flow
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        self.chains_by_block = {}
        
        return
    
    def tag_use(self, chains, loc):
        """ tag 'expr' (which is an assignable item) as being used.
            'parent' is the expression which 'expr' is part of
            (i.e. probably an assignment). """
        
        chains.use(loc)
        
        return
    
    def tag_any_defs(self, chains, loc):
        """ check if expr constitutes a definition (assignment to regloc) """
        
        if type(loc.get()) in (regloc_t, ):
            chains.define(loc)
        
        return
    
    def tag_left_uses(self, chains, loc):
        """ tag any register use that is on the left-hand side of an assignment.
            a regloc at the top level is not a use, it's a definition; however, anything 
            else (for example, what's inside of a dereference) is a use.
            
            i.e:
                eax = ebx + 1 # eax is _defined_
                *(eax) = ebx = 1 # eax is _used_
        """
        
        if type(loc.get()) not in (regloc_t, ):
            #~ print 'not regloc...', repr(loc.get())
            self.tag_expression(chains, loc)
        
        return
    
    def tag_expression(self, chains, loc):
        
        container = loc.container
        stmt = loc.stmt
        expr = loc.get()
        
        if type(expr) == assign_t:
            self.tag_left_uses(chains, operator_location_t(container, stmt, expr, 0))
            self.tag_expression(chains, operator_location_t(container, stmt, expr, 1))
            
            self.tag_any_defs(chains, operator_location_t(container, stmt, expr, 0))
        elif type(expr) in (regloc_t, ):
            self.tag_use(chains, loc)
            
        elif type(expr) in (var_t, arg_t, value_t):
            # none of these are expressions.
            pass
        else:
            # anything else is recursively checked to see if it contains any more assignments.
            for i in range(len(expr.operands)):
                op = expr.operands[i]
                if not op:
                    continue
                loc = operator_location_t(container, stmt, expr, i)
                self.tag_expression(chains, loc)
        
        return
    
    def tag_statement(self, chains, container, stmt):
        
        if type(stmt) == if_t:
            self.tag_expression(chains, statement_location_t(container, stmt))
            
            if stmt.else_expr is None:
                # no fuss about it, 'only' one side to the if means that we 
                # don't have to merge it.
                
                self.tag_container(chains, stmt.then_expr)
            else:
                
                self.tag_container(chains, stmt.then_expr)
                self.tag_container(chains, stmt.else_expr)
            
        elif type(stmt) == goto_t:
            ea = stmt.expr.value
            block = self.flow.blocks[ea]
            self.tag_append_block(block)
        
        elif type(stmt) == statement_t:
            self.tag_expression(chains, statement_location_t(container, stmt))
        
        elif type(stmt) == return_t:
            self.tag_expression(chains, statement_location_t(container, stmt))
            self.return_chains.append(chains)
        else:
            raise RuntimeError('unknown statement type: %s' % (repr(stmt), ))
        
        return
    
    def tag_container(self, chains, container):
        
        for stmt in container:
            self.tag_statement(chains, container, stmt)
            
        return
    
    def find_recursions_to(self, parent):
        """ find any child block which, starting from 'parent', 
            have jump_to's back to this block. """
        
        found = []
        explored = []
        to_explore = [parent, ]
        
        while len(to_explore) > 0:
            cur = to_explore.pop(0)
            explored.append(cur)
            
            for to in cur.jump_to:
                if to == parent:
                    #~ print 'block %x jumps back to %x' % (cur.ea, parent.ea)
                    found.append(cur)
                    continue
                
                if to not in explored and to not in to_explore:
                    to_explore.append(to)
        
        return found
    
    def merge_two_chains(self, left, right):
        
        # for each chain in 'right', merge it into 'left', according to the conditions
        # described below.
        
        for chain in right.chains:
            if chain in left.chains:
                # the exact same chain is already present, probably because 
                # both blocks share a common path leading here. do nothing.
                
                if chain not in right.live and chain in left.live:
                    left.live.remove(chain)
                
                #~ print 'already present', str(chain.defreg), repr([str(o.stmt) for o in chain.defs]), repr([str(o.stmt) for o in chain.uses])
                #~ print 
                continue
            
            if chain not in right.live:
                # if this chain is not 'live' on the right side, we don't actually care 
                # about it because it was probably shadowed by another chain
                # sharing the same register. (by re-assignation to that register)
                left.chains.insert(0, chain)
                
                #~ print 'not live in right', str(chain.defreg), repr([str(o.stmt) for o in chain.defs])
            else:
                # it's live on the right side. first check if it is also live on the left side,
                # and if it is, it means we have a register which is defined in two
                # different code paths to two different values.
                
                # if this register is only live on the right side and not on the left, 
                # simply copy it over.
                
                live_in_left = False
                for _chain in left.live:
                    if _chain.defreg == chain.defreg:
                        # conflicting live registers! add the conflicting 
                        # definition to the chain.
                        live_in_left = True
                        
                        #~ print 'conflicting', repr([str(o.stmt) for o in chain.defs])
                        
                        _chain.defs.extend(chain.defs)
                        _chain.uses.extend(chain.uses)
                
                if not live_in_left:
                    # no conflict here. just copy the chain over.
                    
                    for livechain in left.live:
                        if livechain.defreg == chain.defreg:
                            left.live.remove(livechain)
                            break
                    
                    left.chains.append(chain)
                    left.live.append(chain)
                    
                    #~ print 'no conflict', repr([str(o.stmt) for o in chain.defs])
        
        return
    
    def merge_many_chains(self, _list):
        
        if len(_list) == 0:
            return chains_t()
        
        _list = _list[:]
        chains = _list.pop(0).copy()
        for _chains in _list:
            self.merge_two_chains(chains, _chains)
        
        return chains
    
    def entry_chains(self, block):
        """ calculate the entry (parent) chains for this block. with a non-looping 
        code flow, the def-use chains are very easy to calculate: it consists of all
        def-use chains from all blocks leading to this block merged together.
        
        for a looping flow, i.e. when the parent block has a branch (excl. this one)
        that loops back to the parent block, then the entry def-use chain for
        this block must include the def-use chain for those code paths that lead
        back to the parent block.
        
        note that if there are more than one parent blocks, then all def-use chains
        looping back to any parent blocks is included
        """
        
        # collect precursor blocks, uncluding those that lead back to any parent of this block
        # due to recursion.
        precursor_blocks = block.jump_from[:]
        for parent in block.jump_from:
            precursor_blocks.extend(self.find_recursions_to(parent))
        
        # remove this block from precursors.
        #~ if block in precursor_blocks:
            #~ precursor_blocks.remove(block)
        
        if len(precursor_blocks) == 0:
            return chains_t()
        
        all_chains = [self.block_chains[_block] for _block in precursor_blocks if _block in self.block_chains]
        
        if len(all_chains) == 1:
            return all_chains[0].copy()
        
        chains = self.merge_many_chains(all_chains)
        return chains
    
    def tag_append_block(self, block):
        
        if block not in self.next_blocks and block not in self.done_blocks:
            self.next_blocks.append(block)
        
        return
    
    def can_explore(self, block):
        
        recursions = self.find_recursions_to(block)
        #~ print 'all blocks that are recursion source for', hex(block.ea), repr([hex(o.ea) for o in recursions])
        
        for _block in block.jump_from:
            if _block not in self.done_blocks and _block not in recursions:
                return False
        
        return True
    
    def tag_flow_block(self, _, block):
        
        recursions = self.find_recursions_to(block)
        
        if block in self.done_blocks:
            return
        
        if not self.can_explore(block):
            #~ print 'delaying %x' % block.ea
            if block not in self.next_blocks:
                self.next_blocks.append(block)
            return
        
        #~ print 'exploring %x' % block.ea
        
        chains = self.entry_chains(block)
        
        #~ self.block_live[block] = [o.copy() for o in chains.live]
        #~ print 'keeping lives:', repr([str(o.stmt) for o in self.block_live[block]])
        
        self.tag_container(chains, block.container)
        self.block_chains[block] = chains.copy()
        
        #~ print 'exploring %x done' % block.ea
        
        self.done_blocks.append(block)
        
        if len(recursions) > 0:
            print '%x has recursive code paths' % (block.ea)
            self.recursion_blocks.append(block)
        
        #~ for 
        
        return
    
    def tag_all(self):
        
        self.done_blocks = []
        
        #~ print 'tagging..'
        
        self.block_chains = {}
        self.block_live = {}
        self.next_blocks = [self.flow.entry_block, ]
        self.return_chains = []
        self.recursion_blocks = []
        
        #~ chains = chains_t()
        while len(self.next_blocks) > 0:
            block = self.next_blocks.pop(0)
            self.tag_flow_block(None, block)
        
        print 'recursion pass...'
        for block in self.recursion_blocks:
            if block in self.done_blocks:
                self.done_blocks.remove(block)
                self.next_blocks.append(block)
        
        while len(self.next_blocks) > 0:
            block = self.next_blocks.pop(0)
            self.tag_flow_block(None, block)
        
        assert len(self.flow.return_blocks) == 1, 'we probably need to merge use-def chains here'
        
        return self.return_chains[0]


class simplifier():
    
    def __init__(self, flow):
        
        self.flow = flow
        self.chains = None
        
        self.done_blocks = []
        
        self.simplified = False
        self.expr_fct = None
        
        self.live = []
        
        # local variables
        self.stack_variables = {}
        self.arguments = []
        self.register_variables = []
        
        return
    
    def remove_live(self, oldloc):
        for loc in self.live:
            if loc.get() == oldloc.get():
                self.live.remove(loc)
                break
        return
    
    def collect_live(self, op):
        for loc in self.live:
            if loc.get() == op:
                return loc
        return
    
    def collect_all_live(self, container):
        livelist = []
        liveregs = []
        for loc in self.live:
            if not (loc.get() == self.flow.stackreg) and loc.container == container:
                if loc.get() not in liveregs:
                    liveregs.append(loc.get())
                    livelist.append(loc)
        #~ print 'collected live:', repr(livelist)
        return livelist
    
    def make_arglist(self, container, stmt, call, livelist):
        """ this overly complex piece of code makes sure to add proper use references
            to the newly created argument's def-use chains """
        
        if len(livelist) == 0:
            return None
        
        if len(livelist) == 1:
            argloc = livelist[0]
            useloc = operator_location_t(container, stmt, call, 1)
            useloc.chain = argloc.chain
            argloc.chain.uses.append(useloc)
            return argloc.get().copy()
        
        firstloc = livelist.pop(0)
        first = firstloc.get().copy()
        arglist = None
        for argloc in livelist:
            if arglist is None:
                arglist = comma_t(argloc.get().copy(), first)
                
                useloc = operator_location_t(container, stmt, arglist, 1)
                useloc.chain = firstloc.chain
                firstloc.chain.uses.append(useloc)
            else:
                arglist = comma_t(argloc.get().copy(), arglist)
            
            useloc = operator_location_t(container, stmt, arglist, 0)
            useloc.chain = argloc.chain
            argloc.chain.uses.append(useloc)
        
        return arglist
    
    def collect_assign(self, chains, container, stmt):
        
        if type(stmt.expr) == assign_t and type(stmt.expr.op1) in (regloc_t, ):
            
            _list = chains.get_stmt(stmt)
            if not _list or len(_list['defines']) == 0:
                return
                
            loc = _list['defines'][0]
            op1 = stmt.expr.op1
            
            self.remove_live(loc)
            
            self.live.append(loc)
            #~ print str(loc.get()), 'is live', str(stmt.expr.op2)
        
        return
    
    def collect_call_arguments(self, chains, container, stmt):
        
        if type(stmt.expr) == call_t:
            call = stmt.expr
            #~ callloc = statement_location_t(container, stmt)
        elif (type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t):
            call = stmt.expr.op2
            #~ callloc = operator_location_t(container, stmt, stmt.expr, 1)
        else:
            # not a call...
            
            self.collect_assign(chains, container, stmt)
            return
        
        args = self.collect_all_live(container)
        arglist = self.make_arglist(container, stmt, call, args)
        #~ print 'arglist:', repr(arglist)
        
        call.params = arglist
        
        for loc in args:
            # no longer live after this call...
            self.remove_live(loc)
        
        self.simplified = True
        
        self.collect_assign(chains, container, stmt)
        return
    
    def retag(self, container, stmt, expr, uses, loc):
        """ when an expression is copied (as part of the normal def-use 
        propagation), the newly duplicated regloc_t objects need to be
        inserted into their def-use chains. """
        
        if type(expr) == regloc_t:
            for use in uses:
                if use.get() == expr:
                    #~ print 'retagging', str(expr), 'with', str(use.get())
                    use.chain.uses.append(loc)
                    loc.chain = use.chain
        elif isinstance(expr, expr_t):
            for i in range(len(expr.operands)):
                op = expr.operands[i]
                loc = operator_location_t(container, stmt, expr, i)
                self.retag(container, stmt, op, uses, loc)
        
        return
    
    def simplify_expression(self, chains, container, stmt):
        
        uses = chains.get_stmt(stmt)
        if not uses:
            return
        uses = uses['uses']
        
        for use in uses[:]:
            # we have an arbitraty <stmt> which has a few used variables use[n]
            # these use[n] variables are each defined at def[n]
            
            chain = use.chain # chain this item is part of.
            
            if len(chain.defs) != 1:
                continue
            
            _def = chain.defs[0]
            value = _def.expr.op2 # chain's expression is assign_t, 2nd operand is assignation value
            
            expr = stmt.expr
            if not (type(expr) == assign_t and type(expr.op1) == regloc_t \
                    and type(expr.op2) == regloc_t) and type(value) == call_t:
                # do not simplify if the expression if the value is a call, with the exception
                # that we can simplify if this expression has the form 'reg = reg'
                continue
            
            if use in chain.uses:
                chain.uses.remove(use)
            
            # get the register used in the chain's definition's statement
            deflist = chains.get_stmt(_def.stmt)
            
            use.replace(value.copy())
            
            # simplify the new statement.
            self.flow.simplify_statement(use.stmt)
            
            if deflist:
                self.retag(container, stmt, use.get(), deflist['uses'], use)
            
            if len(chain.uses) == 0:
                #~ print 'simplify out of existance?', str(defchain.definition.stmt)
                _def.container.remove(_def.stmt)
                if chain in chains.chains:
                    chains.chains.remove(chain)
            
            self.simplified = True
        
        return
    
    def simplify_statement(self, chains, container, stmt):
        
        if type(stmt) == if_t:
            self.expr_fct(chains, container, stmt)
            
            self.simplify_container(chains, stmt.then_expr)
            
            if stmt.else_expr:
                self.simplify_container(chains, stmt.else_expr)
            
        elif type(stmt) == goto_t:
            ea = stmt.expr.value
            block = self.flow.blocks[ea]
            self.simplify_block(chains, block)
        
        elif type(stmt) == statement_t:
            self.expr_fct(chains, container, stmt)
        
        elif type(stmt) == return_t:
            self.expr_fct(chains, container, stmt)
            
        else:
            raise RuntimeError('unknown statement type: %s' % (repr(stmt), ))
        
        return
    
    def simplify_container(self, chains, container):
        
        for stmt in container[:]:
            self.simplify_statement(chains, container, stmt)
        
        return
    
    def simplify_block(self, chains, block):
        
        if block in self.done_blocks:
            #~ print 'already done block:', hex(block.ea)
            return
        
        self.done_blocks.append(block)
        
        self.simplify_container(chains, block.container)
        
        return
    
    def tag(self):
        t = tagger(self.flow)
        self.chains = t.tag_all()
        return
    
    def simplify(self, fct):
        """ after all def-uses are tagged properly, this will replace
            any single use (any def-use chain with a single use) with 
            the definition itself. """
        
        self.expr_fct = fct
        self.simplified = False
        
        self.live = []
        self.done_blocks = []
        block = self.flow.entry_block
        self.simplify_block(self.chains, block)
        
        return self.simplified
    
    def remove_unused(self):
        
        for chain in self.chains.chains[:]:
            
            if len(chain.defs) > 0 and len(chain.uses) == 0:
                # remove statement if definition is never used..
                
                for _def in chain.defs:
                    if type(_def.stmt.expr) == assign_t and \
                            type(_def.stmt.expr.op2) == call_t:
                        # avoid removing calls for obvious reasons
                        continue
                    
                    _def.container.remove(_def.stmt)
        
        return
    
    def mark_local_variables(self):
        
        i = 0
        
        for chain in self.chains.chains[:]:
            for _def in chain.defs:
                if _def.get() == self.flow.stackreg:
                    continue
                _def.get().index = i
            for use in chain.uses:
                if use.get() == self.flow.stackreg:
                    continue
                use.get().index = i
            
            i += 1
        
        return
    
    def stack_variable(self, expr):
        
        assert (type(expr) == sub_t and type(expr.op1) == regloc_t and \
                expr.op1 == self.flow.stackreg and type(expr.op2) == value_t)
        
        index = -(expr.op2.value)
        
        if index in self.stack_variables:
            return self.stack_variables[index].copy()
        
        var = var_t(expr.copy())
        var.name = 'v%u' % (self.varn, )
        self.varn += 1
        
        self.stack_variables[index] = var
        
        return var
    
    def rename_stack_variables_iter_expr(self, chains, container, stmt, expr):
        
        if type(expr) == deref_t:
            #~ print 'deref', str(expr)
            
            if type(expr.op) == sub_t and type(expr.op.op1) == regloc_t and \
                    expr.op.op1 == self.flow.stackreg and type(expr.op.op2) == value_t:
                return self.stack_variable(expr.op)
            
        elif type(expr) == sub_t and type(expr.op1) == regloc_t and \
                    expr.op1 == self.flow.stackreg and type(expr.op2) == value_t:
            
            var =  self.stack_variable(expr)
            return address_t(var)
            
        elif isinstance(expr, expr_t):
            for i in range(len(expr.operands)):
                op = expr.operands[i]
                expr.operands[i] = self.rename_stack_variables_iter_expr(chains, container, stmt, op)
        
        return expr
    
    def rename_stack_variables_callback(self, chains, container, stmt):
        
        stmt.expr = self.rename_stack_variables_iter_expr(chains, container, stmt, stmt.expr)
        
        return
    
    def rename_stack_variables(self):
        
        s.simplify(s.rename_stack_variables_callback)
        
        return
    
    def rename_local_variables(self):
        
        self.argn = 0
        self.varn = 0
        
        for chain in self.chains.chains[:]:
            
            if len(chain.defs) == 0:
                argloc = chain.uses[0]
                argreg = argloc.get()
                
                if argreg == self.flow.stackreg:
                    continue
                
                arg = arg_t(argreg)
                arg.name = 'a%u' % (self.argn, )
                self.argn += 1
                argloc.replace(arg)
                
                self.arguments.append(namedchain_t(chain, arg.name))
            else:
                
                if chain.defreg == self.flow.stackreg:
                    continue
                
                varname = 'v%u' % (self.varn, )
                self.varn += 1
                
                for defloc in chain.defs:
                    var = var_t(defloc.get().copy())
                    var.name = varname
                    defloc.replace(var)
                
                for useloc in chain.uses:
                    var = var_t(useloc.get().copy())
                    var.name = varname
                    useloc.replace(var)
                
                #~ print 'newly tagged var', repr([str(o.stmt) for o in chain.defs]), repr([str(o.stmt) for o in chain.uses])
                self.register_variables.append(namedchain_t(chain, varname))
        
        self.rename_stack_variables()
        
        return

class namedchain_t(object):
    
    def __init__(self, chain, name):
        self.chain = chain
        self.name = name
        return

print 'here:', idc.here()
func = idaapi.get_func(idc.here())

f = flow_t(func.startEA)
f.reduce_blocks()

print '----1----'
print str(f)
print '----1----'

# first combination pass: collapse some simple goto flows
#~ f.combine_blocks()

# simplify it.
s = simplifier(f)

# basically here we compute the def-use chains and 'mark' each 
# instance of a variable with an index. An instance in, this case,
# is all definitions and their uses of a single register
s.tag()
s.mark_local_variables()
#~ s.tag()
s.simplify(s.simplify_expression)
if s.simplify(s.collect_call_arguments):
    # simplify again after argument call resolution...
    s.simplify(s.simplify_expression)
s.remove_unused()
s.rename_local_variables()

f.combine_blocks()

#~ for chain in s.chains.chains:
    #~ print 'def', repr(chain.defs), repr([str(o.stmt) for o in chain.defs])
    #~ print 'use', repr(chain.uses), repr([str(o.stmt) for o in chain.uses])

print '----2----'
print 'arguments:', ', '.join([arg.name for arg in s.arguments])
print 'variables:'
for var in s.register_variables:
    print '%s; // %s' % (var.name, var.chain.defreg)
for index,var in s.stack_variables.iteritems():
    print '%s; // esp%s' % (var.name, index)
print str(f)
print '----2----'
