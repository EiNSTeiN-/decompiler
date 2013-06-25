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
    """ this class follows all paths in the function and tags registers.
    The main task here is to differenciate all memory locations from each
    other, so that each time a register is reassigned it is considered
    different from previous assignments. After doing this, each memory
    location should be in a form somewhat similar to static single assignment
    form, where all locations are defined once and possibly used zero, once or 
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
    
    def __init__(self, flow, conv):
        self.flow = flow
        
        # keep track of any block which we have already walked into, because at
        # this stage we may still encounter recursion (gotos that lead backwards).
        self.done_blocks = []
        
        self.tagged_pairs = []
        
        self.fct_arguments = []
        
        
        self.conv = conv
        
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
            pos = stmt.index()
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
                _container.insert(_stmt.index(), statement_t(expr))
            else:
                # insert the new assignation
                expr = assign_t(external.copy(), _reg.copy())
                _container.insert(_stmt.index()+1, statement_t(expr))
        
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
    """ an instance of a register (either use or definition). """
    
    def __init__(self, block, stmt, reg):
        
        self.block = block
        self.stmt = stmt
        self.reg = reg
        
        return
    
    def __eq__(self, other):
        return other.block == self.block and other.stmt == self.stmt and \
                other.reg == self.reg

class chain_t(object):
    """ this object holds all instances of a single register. those 
    instances can be definitions or uses. a register is 'defined' 
    when it appears on the left side of an assing_t expression, 
    such as 'eax = 0' except if it is part of another construct, 
    such that '*(eax) = 0' does not constitute a definition of 
    eax but a use of eax.
    """
    
    def __init__(self, flow, defreg):
        
        self.flow = flow
        self.defreg = defreg
        self.instances = []
        
        return
    
    def __repr__(self):
        s = '<chain %s: %s>' % (str(self.defreg), repr([str(i.stmt) for i in self.instances]))
        return s
    
    def new_instance(self, instance):
        #~ if instance in self.instances:
            #~ return
        self.instances.append(instance)
        return
    
    @property
    def defines(self):
        return [instance for instance in self.instances if instance.reg.is_def]
    
    @property
    def uses(self):
        return [instance for instance in self.instances if not instance.reg.is_def]
    
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
    
# what are we collecting now
COLLECT_REGISTERS = 1
COLLECT_FLAGS = 2
COLLECT_ARGUMENTS = 4
COLLECT_VARIABLES = 8
COLLECT_DEREFS = 16
COLLECT_ALL = COLLECT_REGISTERS | COLLECT_FLAGS | COLLECT_ARGUMENTS | \
                COLLECT_VARIABLES | COLLECT_DEREFS

PROPAGATE_ANY = 1 # any expression
PROPAGATE_STACK_LOCATIONS = 2 # only stack locations
PROPAGATE_REGISTERS = 4 # only register locations.
PROPAGATE_FLAGS = 8 # only flagloc_t

# if set, propagate only definitions with a single use. otherwise,
# expressions with multiple uses can be propagated (this is 
# necessary for propagating stack variables, for example)
PROPAGATE_SINGLE_USES = 512

class simplifier(object):
    """ this class is used to make transformations on the code flow, 
    such as replacing uses by their definitions, removing restored
    registers, etc. """
    
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
        if self.flags & COLLECT_DEREFS and type(expr) == deref_t:
            return True
        
        return False
    
    def find_reg_chain(self, chains, reg):
        """ find the chain that matches this exact register. """
        
        for chain in chains:
            if chain.defreg == reg:
                return chain
        
        return
    
    def get_statement_chains(self, block, stmt, chains):
        """ given a statement, collect all registers that appear 
            in it and stuff them in their respective chains. """
        
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
                chain = chain_t(self.flow, reg)
                chains.append(chain)
            instance = instance_t(block, stmt, reg)
            chain.new_instance(instance)
        
        if type(stmt) == return_t:
            self.return_chains[block] = chains[:]
        
        return
    
    def get_block_chains(self, block, chains):
        """ iterate over a block and build chains. """
        
        if block in self.done_blocks:
            return
        
        self.done_blocks.append(block)
        
        for stmt in list(block.container.statements):
            self.get_statement_chains(block, stmt, chains)
        
        return
    
    def get_chains(self):
        """ return a list of all chains that should be collected 
            according to the 'flags' given. """
        
        self.done_blocks = []
        chains = []
        self.get_block_chains(self.flow.entry_block, chains)
        
        return chains
    
    def can_propagate(self, chain, flags):
        """ return True if this chain can be propagated. """
        
        defines = chain.defines
        uses = chain.uses
        
        # prevent removing anything without uses during propagation. we'll do it later.
        if len(uses) == 0 or len(defines) == 0:
            return False
        
        # no matter what, we cannot propagate if there is more than 
        # one definition for this chain with the exception where all 
        # the definitions are the same.
        if len(defines) > 1 and not chain.all_same_definitions():
            return False
        
        definstance = defines[0]
        stmt = definstance.stmt
        if type(stmt.expr) != assign_t:
            # this is not possible in theory.
            return False
        
        # get the target of the assignement.
        value = stmt.expr.op2
        
        # never propagate function call if it has more than one use...
        if type(value) == call_t and len(uses) > 1:
            return False
        
        # prevent multiplying statements if they have more than one use.
        # this should be the subject of a more elaborate algorithm in order
        # to propagate simple expressions whenever possible but limit
        # expression complexity at the same time.
        
        if type(stmt.expr.op1) == regloc_t:
            return True
        
        if len(uses) > 1 and (flags & PROPAGATE_SINGLE_USES) != 0:
            return False
        
        if (flags & PROPAGATE_ANY):
            return True
        
        if self.flow.arch.is_stackvar(value) and (flags & PROPAGATE_STACK_LOCATIONS):
            return True
        
        if type(value) == regloc_t and (flags & PROPAGATE_REGISTERS):
            return True
        
        if type(value) == flagloc_t and (flags & PROPAGATE_FLAGS):
            return True
        
        return False
    
    def propagate(self, chains, chain):
        """ take all uses and replace them by the right side of the definition.
        returns True if the propagation was successful. """
        
        defines = chain.defines
        
        definstance = defines[0]
        stmt = definstance.stmt
        
        # get the target of the assignement.
        value = stmt.expr.op2
        
        ret = False
        
        for useinstance in list(chain.uses):
            _stmt = useinstance.stmt
            _index = _stmt.index()
            
            # check if the instance can be propagated. the logic is to avoid
            # propagating past a redefinition of anything that is used in this 
            # statement. eg. in the series of statements 'y = x; x = 1; z = y;' 
            # the 'y' assignement cannot be propagated because of the assignement
            # to 'x' later.
            right_uses = [reg for reg in value.iteroperands() if self.should_collect(reg)]
            prevent = False
            for reg in right_uses:
                
                other_chain = self.find_reg_chain(chains, reg)
                if not other_chain:
                        continue
                for inst in other_chain.instances:
                    if not inst.stmt.container:
                        continue
                    #~ if inst.reg.is_def:
                        #~ print 'is def', str(inst.reg)
                    if inst.stmt.index() > _index:
                        continue
                    if inst.reg.is_def and inst.stmt.index() > stmt.index():
                        prevent = True
                        break
            
            if prevent:
                print 'prevent...', str(stmt), 'into', str(_stmt)
                continue
            
            useinstance.reg.replace(value.copy())
            
            chain.instances.remove(useinstance)
            filters.simplify_expressions.run(_stmt.expr, deep=True)
            
            # handle special case where statement is simplified into itself
            if type(_stmt.expr) == assign_t and _stmt.expr.op1 == _stmt.expr.op2:
                _stmt.remove()
            
            ret = True
        
        # if definition was propagated fully, then remove its definition statement
        if len(chain.uses) == 0:
            for define in defines:
                define.stmt.remove()
            chains.remove(chain)
        
        return ret

    def propagate_all(self, flags):
        """ collect all chains in this function flow, then propagate 
            them if possible. """
        
        while True:
            redo = False
            
            chains = self.get_chains()
            
            for chain in chains:
                
                if not self.can_propagate(chain, flags):
                    continue
                
                redo = self.propagate(chains, chain) or redo
            
            if not redo:
                break
        
        return
    
    def remove_unused_definitions(self):
        """ Remove definitions that don't have any uses.
            Do it recursively, because as we remove some, others may becomes
            unused.
        """
        
        while True:
            redo = False
            
            chains = self.get_chains()
            for chain in chains:
                
                if len(chain.uses) > 0:
                    continue
                
                for instance in chain.defines:
                    
                    stmt = instance.stmt
                    
                    if type(stmt.expr) == call_t:
                        # do not eliminate calls
                        continue
                    elif type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
                        # simplify 'reg = call()' form if reg is a register and is no longer used.
                        if type(stmt.expr.op1) == regloc_t:
                            stmt.expr = stmt.expr.op2
                        continue
                    
                    # otherwise remove the statement
                    stmt.remove()
                    
                    redo = True
            
            if not redo:
                break
        
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
                #~ print 'restored', str(defreg)
                
                # pop all statements in which the restored location appears
                for inst in chain.instances:
                    inst.stmt.remove()
                
                reg = defreg.copy()
                reg.index = None
                restored_regs.append(reg)
        
        print 'restored regs', repr([str(r) for r in restored_regs])
        
        return restored_regs
    
    class arg_collector(object):
        
        def __init__(self, flow, conv, chains):
            self.flow = flow
            self.conv = conv
            self.chains = chains
            return
            
        def iter(self, block, container, stmt):
            
            if type(stmt.expr) == call_t:
                call = stmt.expr
            
            elif type(stmt.expr) == assign_t and type(stmt.expr.op2) == call_t:
                call = stmt.expr.op2
            
            else:
                return
            
            live = []
            
            for chain in self.chains:
                for instance in chain.instances:
                    inst_index = instance.stmt.index()
                    if instance.stmt.container != container:
                        continue
                    if inst_index >= stmt.index():
                        continue
                    if instance.reg.is_def:
                        live.append(instance.stmt)
            
            self.conv.process_stack(self.flow, block, stmt, call, live)
            
            return
    
    def collect_argument_calls(self, conv):
        
        chains = self.get_chains()
        c = self.arg_collector(self.flow, conv, chains)
        iter = flow_iterator(self.flow, statement_iterator=c.iter)
        iter.do()
        
        return

    def glue_increments_collect(self, block, container):
        """ for a statement, get all registers that appear in it. """
        
        chains = []
        
        for stmt in container.statements:
            regs = [reg for reg in stmt.expr.iteroperands() if self.should_collect(reg)]
            
            for reg in regs:
                chain = self.find_reg_chain(chains, reg)
                if not chain:
                    chain = chain_t(self.flow, reg)
                    chains.append(chain)
                instance = instance_t(block, stmt, reg)
                chain.new_instance(instance)
        
        #~ print 'current', str(block)
        
        while True:
            
            redo = False
            
            # now for each chain, check if they contain increments
            for chain in chains:
                
                continuous = []
                
                i = 0
                while i < len(chain.instances):
                    
                    all = []
                    j = i
                    while True:
                        if j >= len(chain.instances):
                            break
                        
                        next = chain.instances[j]
                        #~ next_index = next.stmt.index()
                        #~ print 'b', str(next.stmt)
                        
                        if len([a for a in all if a.stmt == next.stmt]) > 0:
                            j += 1
                            continue
                        
                        #~ if last_index + 1 != next_index:
                            #~ break
                        
                        if not self.is_increment(chain.defreg, next.stmt.expr) or \
                                not next.reg.is_def:
                            break
                        
                        #~ last_index = next_index
                        all.append(next)
                        j += 1
                    
                    if len(all) == 0:
                        i += 1
                        continue
                    
                    #~ j += 1
                    if j < len(chain.instances):
                        next = chain.instances[j]
                        #~ next_index = next.stmt.index()
                        #~ if last_index + 1 == next_index:
                        all.append(next)
                    
                    if i > 0:
                        this = chain.instances[i-1]
                        if not this.reg.is_def:
                            #~ i = chain.instances.index(this)
                            expr = this.stmt.expr
                            #~ last_index = this.stmt.index()
                            #~ print 'a', str(expr)
                            
                            all.insert(0, this)
                    continuous.append(all)
                    
                    i = j
                
                #~ for array in continuous:
                    #~ print 'continuous statements:'
                    #~ for instance in array:
                        #~ print '->', str(instance.stmt)
                
                # at this point we are guaranteed to have a list with possibly 
                # a statement at the beginning, one or more increments in the 
                # middle, and possibly another statement at the end.
                
                for array in continuous:
                    pre = array.pop(0) if not self.is_increment(chain.defreg, array[0].stmt.expr) else None
                    post = array.pop(-1) if not self.is_increment(chain.defreg, array[-1].stmt.expr) else None
                    
                    if pre:
                        instances = self.get_nonincrements_instances(pre.stmt.expr, chain.defreg)
                        
                        #~ print 'a', repr([str(reg) for reg in instances])
                        while len(instances) > 0 and len(array) > 0:
                            increment = array.pop(0)
                            cls = postinc_t if type(increment.stmt.expr.op2) == add_t else postdec_t
                            instance = instances.pop(-1)
                            #~ pre.stmt.expr = self.merge_increments(pre.stmt.expr, instance, cls)
                            instance.replace(cls(instance.copy()))
                            increment.stmt.remove()
                            chain.instances.remove(increment)
                    
                    if post:
                        instances = self.get_nonincrements_instances(post.stmt.expr, chain.defreg)
                        
                        #~ print 'b', repr([str(reg) for reg in instances])
                        while len(instances) > 0 and len(array) > 0:
                            increment = array.pop(0)
                            cls = preinc_t if type(increment.stmt.expr.op2) == add_t else predec_t
                            instance = instances.pop(-1)
                            #~ post.stmt.expr = self.merge_increments(post.stmt.expr, instance, cls)
                            instance.replace(cls(instance.copy()))
                            increment.stmt.remove()
                            chain.instances.remove(increment)
            
            if not redo:
                break
        
        return
    
    def get_nonincrements_instances(self, expr, defreg):
        """ get instances of 'reg' that are not already surrounded by an increment or decrement """
        
        instances = [reg for reg in expr.iteroperands() if reg == defreg]
        increments = [reg for reg in expr.iteroperands() if type(reg) in (preinc_t, postinc_t, predec_t, postdec_t)]
        
        real_instances = []
        for instance in instances:
            found = False
            for increment in increments:
                if increment.op is instance:
                    found = True
                    break
            if not found:
                real_instances.append(instance)
        
        return real_instances
    
    def is_increment(self, what, expr):
        return (type(expr) == assign_t and type(expr.op2) in (add_t, sub_t) and \
                    type(expr.op2.op2) == value_t and expr.op2.op2.value == 1 and \
                    expr.op1 == expr.op2.op1 and expr.op1 == what)
    
    def glue_increments(self):
        
        iter = flow_iterator(self.flow, container_iterator=self.glue_increments_collect)
        iter.do()
        
        return

class flow_iterator(object):
    """ Helper class for iterating a flow_t object.
    
    The following callbacks can be used:
        block_iterator(block_t)
        container_iterator(block_t, container_t)
        statement_iterator(block_t, container_t, statement_t)
        expression_iterator(block_t, container_t, statement_t, expr_t)
    
    any callback can return False to stop the iteration.
    """
    
    def __init__(self, flow, **kwargs):
        self.flow = flow
        
        self.block_iterator = kwargs.get('block_iterator')
        self.container_iterator = kwargs.get('container_iterator')
        self.statement_iterator = kwargs.get('statement_iterator')
        self.expression_iterator = kwargs.get('expression_iterator')
        
        return
    
    def do_expression(self, block, container, stmt, expr):
        
        r = self.expression_iterator(block, container, stmt, expr)
        if r is False:
            # stop iterating.
            return False
        
        if isinstance(expr, expr_t):
            for i in range(len(expr)):
                r = self.do_expression(block, container, stmt, expr[i])
                if r is False:
                    # stop iterating.
                    return False
        
        return
    
    def do_statement(self, block, container, stmt):
        
        if self.statement_iterator:
            r = self.statement_iterator(block, container, stmt)
            if r is False:
                # stop iterating.
                return
        
        if self.expression_iterator and stmt.expr is not None:
            r = self.do_expression(block, container, stmt, stmt.expr)
            if r is False:
                # stop iterating.
                return False
        
        if type(stmt) == goto_t and type(stmt.expr) == value_t:
            block = self.flow.get_block(stmt)
            self.do_block(block)
            return
        
        for _container in stmt.containers:
            r = self.do_container(block, _container)
            if r is False:
                # stop iterating.
                return False
        
        return
    
    def do_container(self, block, container):
        
        if self.container_iterator:
            r = self.container_iterator(block, container)
            if r is False:
                return
        
        for stmt in container.statements:
            r = self.do_statement(block, container, stmt)
            if r is False:
                # stop iterating.
                return False
        
        return
    
    def do_block(self, block):
        
        if block in self.done_blocks:
            return
        
        self.done_blocks.append(block)
        
        if self.block_iterator:
            r = self.block_iterator(block)
            if r is False:
                # stop iterating.
                return False
        
        r = self.do_container(block, block.container)
        if r is False:
            # stop iterating.
            return False
        
        return
    
    def do(self):
        
        self.done_blocks = []
        block = self.flow.entry_block
        self.do_block(block)
        
        return

RENAME_STACK_LOCATIONS = 1
RENAME_REGISTERS = 2

class renamer(object):
    """ this class takes care of renaming variables. stack locations and 
    registers are wrapped in var_t and arg_t if they are respectively 
    local variables or function arguments.
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
    
    def stack_variable(self, expr):
        
        assert self.flow.arch.is_stackvar(expr)
        
        if type(expr) == regloc_t and self.flow.arch.is_stackreg(expr):
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
                return self.reg_variables[reg].copy()
        
        var = var_t(expr)
        self.reg_variables[expr] = var
        
        var.name = 'v%u' % (renamer.varn, )
        renamer.varn += 1
        
        return var
    
    def reg_argument(self, expr):
        
        assert type(expr) == regloc_t
        
        for reg in self.reg_arguments:
            if reg == expr:
                return self.reg_arguments[reg].copy()
        
        arg = arg_t(expr)
        self.reg_arguments[expr] = arg
        
        name = 'a%u' % (renamer.argn, )
        arg.name = name
        renamer.argn += 1
        
        return arg
    
    def rename_variables_callback(self, block, container, stmt, expr):
        
        if self.flags & RENAME_STACK_LOCATIONS:
            # stack variable value
            if type(expr) == deref_t and self.flow.arch.is_stackvar(expr.op):
                var = self.stack_variable(expr.op.copy())
                expr.replace(var)
                return
        
            # stack variable address
            if self.flow.arch.is_stackvar(expr):
                var = self.stack_variable(expr.copy())
                expr.replace(address_t(var))
                return 
        
        if self.flags & RENAME_REGISTERS:
            if type(expr) == regloc_t and expr in self.fct_arguments:
                arg = self.reg_argument(expr.copy())
                expr.replace(arg)
                return
            
            if type(expr) == regloc_t:
                var = self.reg_variable(expr.copy())
                expr.replace(var)
                return
        
        return
    
    def wrap_variables(self):
        iter = flow_iterator(self.flow, expression_iterator = self.rename_variables_callback)
        iter.do()
        return

def check_stack_alignment(flow):
    
    # __attribute__((optimize("align-functions=16")))
    
    for stmt in flow.entry_block.container:
        
        match = assign_t(flow.arch.stackreg.copy(), and_t(flow.arch.stackreg.copy(), value_t(0xfffffff0L)))
        #~ print repr(stmt.expr), repr(match)
        
        if stmt.expr == match:
            stmt.remove()
            print str(stmt), '; function is __attribute__((optimize("align-functions=16")))'
            break
    
    return

def main():
    
    print 'here:', idc.here()
    func = idaapi.get_func(idc.here())

    arch = arch_intel()
    f = flow_t(func.startEA, arch)
    f.prepare_blocks()

    print '----1----'
    print str(f)
    print '----1----'

    check_stack_alignment(f)

    # tag all registers so that each instance of a register can be uniquely identified.
    # during this process we also take care of matching registers to their respective 
    # function calls.
    #~ conv = callconv.stdcall()
    conv = callconv.systemv_x64_abi()
    t = tagger(f, conv)
    t.tag_all()

    print '1'
    # remove special flags (eflags) definitions that are not used, just for clarity
    s = simplifier(f, COLLECT_FLAGS)
    s.remove_unused_definitions()

    print '2'
    # After registers are tagged, we can replace their uses by their definitions. this 
    # takes care of eliminating any instances of 'esp' which clears the way for 
    # determining stack variables correctly.
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_STACK_LOCATIONS)
    s = simplifier(f, COLLECT_REGISTERS)
    s.remove_unused_definitions()

    print '3'
    # rename stack variables to differenciate them from other dereferences.
    r = renamer(f, RENAME_STACK_LOCATIONS)
    r.wrap_variables()

    # collect function arguments that are passed on the stack
    s = simplifier(f, COLLECT_ALL)
    s.collect_argument_calls(conv)

    print '3.1'
    # This propagates special flags.
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)

    print '4'
    # At this point we must take care of removing increments and decrements
    # that are in their own statements and "glue" them to an adjacent use of 
    # that location.
    s = simplifier(f, COLLECT_ALL)
    s.glue_increments()
    
    # re-propagate after gluing pre/post increments
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_REGISTERS | PROPAGATE_FLAGS)
    
    print '5'
    s = simplifier(f, COLLECT_ALL)
    s.propagate_all(PROPAGATE_ANY | PROPAGATE_SINGLE_USES)

    print '6'
    # eliminate restored registers. during this pass, the simplifier also collects 
    # stack variables because registers may be preserved on the stack.
    s = simplifier(f, COLLECT_REGISTERS | COLLECT_VARIABLES)
    s.process_restores()
    # ONLY after processing restores can we do this; any variable which is assigned
    # and never used again is removed as dead code.
    s = simplifier(f, COLLECT_REGISTERS)
    s.remove_unused_definitions()

    print '7'
    # rename registers to pretty names.
    r = renamer(f, RENAME_REGISTERS)
    r.fct_arguments = t.fct_arguments
    r.wrap_variables()

    # after everything is propagated, we can combine blocks!
    f.combine_blocks()

    print '----2----'
    print str(f)
    print '----2----'


if __name__ == '__main__':
    main()
