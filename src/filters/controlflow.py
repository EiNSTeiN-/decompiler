""" Control flow simplification algorithms.

This file contains algorithms for transforming the control flow into the most
readable form possible.

When the run() routine is called, the control flow is mostly flat, and
consist mostly of normal statements, conditional jump statements of the form
'if(...) goto ...' and unconditional jump statements of the form 'goto ...' 
(without preceding condition). Most of the work done here is applying simple
algorithms to eliminate goto statements.
"""

import simplify_expressions

from expressions import *
from statements import *

__block_filters__ = [] # filters that are applied to a flow block
__container_filters__ = [] # filters that are applied to a container (i.e. inside a then-branch of an if_t)

def is_if_block(block):
    """ return True if the last statement in a block is a goto 
        statement and the next-to-last statement is a if_t and 
        the if_t also contains a goto as last statement. """
    
    if len(block.container) < 2:
        return False
    
    stmt = block.container[-2]
    goto = block.container[-1]
    
    if type(stmt) == if_t and type(goto) == goto_t and \
            len(stmt.then_expr) == 1 and not stmt.else_expr and \
            type(stmt.then_expr[0]) == goto_t:
        return True
    
    return False

def invert_goto_condition(block):
    """ invert the goto at the end of a block for the goto in 
        the if_t preceding it """
    
    stmt = block.container[-2]
    stmt.then_expr[0], block.container[-1] = block.container[-1], stmt.then_expr[0]
    
    stmt.expr = b_not_t(stmt.expr.copy())
    simplify_expressions.run(stmt.expr, deep=True)
    
    return

def combine_if_blocks(flow, this, next):
    """ combine two if_t that jump to the same destination into a boolean or expression. """
    
    left = [this.container[-1].expr.value, this.container[-2].then_expr[0].expr.value]
    right = [next.container[-1].expr.value, next.container[-2].then_expr[0].expr.value]
    
    dest = list(set(left).intersection(set(right)))
    
    if len(dest) == 1:
        # both blocks have one jump in common.
        dest = dest[0]
        
        if this.container[-1].expr.value == dest:
            invert_goto_condition(this)
        
        if next.container[-1].expr.value == dest:
            invert_goto_condition(next)
        
        other = flow.blocks[next.container[-1].expr.value]
        
        if other == this:
            cls = b_and_t
        else:
            cls = b_or_t
        
        stmt = this.container[-2]
        stmt.expr = cls(stmt.expr.copy(), next.container[-2].expr.copy())
        simplify_expressions.run(stmt.expr, deep=True)
        
        this.jump_to.remove(next)
        next.jump_from.remove(this)
        flow.blocks[dest].jump_from.remove(next)
        
        other.jump_from.remove(next)
        
        if other != this:
            other.jump_from.append(this)
            this.jump_to.append(other)
        this.container[-1] = next.container[-1]
        
        return True
    
    return False

def combine_conditions(flow, block):
    """ combine two ifs into a boolean or (||) or a boolean and (&&). """
    
    if not is_if_block(block):
        return False
    
    for next in block.jump_to:
        if not is_if_block(next) or len(next.container) != 2:
            continue
        
        if combine_if_blocks(flow, block, next):
            return True
    
    return False
__block_filters__.append(combine_conditions)


class loop_paths_t(object):
    
    def __init__(self, flow, block):
        self.flow = flow
        self.paths = []
        self.origin = block
        self.find_all_recursion_paths(block, [block, ])
        return
    
    def is_recursive(self):
        return len(self.paths) > 0
    
    def all_blocks(self):
        return list(set([b for p in self.paths for b in p]))
    
    def can_jump_to(self, block, dstblock):
        
        container = block.container
        if type(container[-1]) != goto_t:
            return False
        
        if container[-1].expr.value == dstblock.ea:
            return True
        
        if type(container[-2]) == if_t and \
                len(container[-2].then_expr) == 1 and \
                type(container[-2].then_expr[0]) == goto_t and \
                container[-2].then_expr[0].expr.value == dstblock.ea:
            return True
        
        return False
    
    def find_all_recursion_paths(self, block, curpath):
        
        for dest in block.jump_to:
            if not self.can_jump_to(block, dest):
                continue
            
            if self.origin == dest:
                self.paths.append(curpath[:])
                continue
            
            #~ if len(dest.jump_from) > 1:
                #~ good = False
                #~ for src in dest.jump_from:
                    #~ if len([p for p in self.paths if src in p]) > 0:
                        #~ good=True
                #~ if not good:
                #~ continue
            
            if dest in curpath:
                # destination is in current path..
                continue
            
            self.find_all_recursion_paths(dest, curpath[:] + [dest, ])
        
        return
    
    def longest_path(self):
        
        if len(self.paths) == 0:
            return
        
        #~ print 'paths'
        maxlen = len(self.paths[0])
        chosen = None
        
        #~ print 'path', repr([hex(b.ea) for b in chosen])
        for p in self.paths:
            #~ if len([b for b in p if len(b.jump_from) > 1]) != 0:
                #~ continue
            if p[0] == self.origin and (not chosen or len(p) > maxlen):
                maxlen = len(p)
                chosen = p
            #~ print 'path', repr([hex(b.ea) for b in p])
        
        assert chosen and chosen[0] == self.origin
        
        return chosen[:]
    
    def is_same_loop(self, path):
        for _path in self.paths:
            if sorted(path[:]) == sorted(_path[:]):
                return True
        return False
    
    def remove_same_paths(self, other):
        for path in self.paths[:]:
            if other.is_same_loop(path):
                self.paths.remove(path)
        return

def switch_goto_if_needed(block, dstblock):
    """ if the last item at the end of 'block' is a goto to dstblock, do nothing,
        otherwise invert that goto with the one in the if_t in the next-to-last
        position. """
    
    container = block.container
    assert type(container[-1]) == goto_t
    
    if container[-1].expr.value == dstblock.ea:
        return
    
    if len(container) < 2:
        return
    
    assert type(container[-2]) == if_t
    assert len(container[-2].then_expr) == 1
    assert type(container[-2].then_expr[0]) == goto_t
    assert container[-2].then_expr[0].expr.value == dstblock.ea
    
    # invert goto_t destinations
    container[-1].expr.value, container[-2].then_expr[0].expr.value = \
        container[-2].then_expr[0].expr.value, container[-1].expr.value
    
    container[-2].expr = b_not_t(container[-2].expr.copy())
    simplify_expressions.run(container[-2].expr, deep=True)
    
    return

def append_block(flow, block, next):
    
    assert type(block.container[-1]) == goto_t
    
    goto = block.container[-1]
    
    # remove goto
    flow.remove_goto(block, goto)
    
    # fixup references to the block that is going to disapear.
    for src in next.jump_from[:]:
        src.jump_to.remove(next)
        src.jump_to.append(block)
        block.jump_from.append(src)
    
    for dst in next.jump_to[:]:
        dst.jump_from.remove(next)
        dst.jump_from.append(block)
        block.jump_to.append(dst)
    
    # append next block's elements
    block.container[:] = block.container[:] + next.container[:]
    
    return

def change_loop_continues(flow, parent_block, container, first_block, exit_block):
    """ if 'block' ends with a goto_t that leads back to first_block, 
        then change it into a continue_t. """
    
    for stmt in container.statements:
        
        if type(stmt) == goto_t:
            
            if parent_block == first_block and stmt == parent_block.container[-1]:
                continue
            
            if flow.get_block(stmt) == first_block:
                idx = stmt.container.index(stmt)
                container = stmt.container
                flow.remove_goto(parent_block, stmt)
                container.insert(idx, continue_t())
        else:
            change_loop_continues(flow, parent_block, stmt, first_block, exit_block)
    
    return

def make_into_loop(flow, loop_path, all_loop_blocks):
    """ try to make a block into a while(), do-while or for() loop.
    
        'loop_path' is a list of blocks which constitute the
            most likely main path through the loop.
        'all_loop_blocks' is a list of all blocks in the loop, including
            those not on the main path through the loop.
    """
    #~ print 'making into a loop'
    
    exit_block = None
    loop_cls = None
    condition = None
    
    first = loop_path[0]
    last = loop_path[-1]
    
    # if the next to last statement in the main path is a if_t
    # which contains a goto which jumps out of the loop, then 
    # we have a do-while() and the goto destination is the exit
    # block.
    if len(last.container) >= 2 and type(last.container[-1]) == goto_t and \
            type(last.container[-2]) == if_t and \
            type(last.container[-2].then_expr[0]) == goto_t and \
            (flow.get_block(last.container[-1]) == first or \
                flow.get_block(last.container[-2].then_expr[0]) == first) and \
            (flow.get_block(last.container[-1]) not in all_loop_blocks or \
                flow.get_block(last.container[-2].then_expr[0]) not in all_loop_blocks):
        
        left = flow.get_block(last.container[-1])
        right = flow.get_block(last.container[-2].then_expr[0])
        if right == first:
            # the goto_t inside the if_t leads to the beginning 
            # of the loop, then invert both gotos
            
            switch_goto_if_needed(last, right)
            exit_block = left
        else:
            exit_block = right
        
        loop_cls = do_while_t
        condition = last.container[-2]
        condition_block = last
    
    # if the very last block in the main path ends in a goto
    # to the beginning of the loop, then we have a while() loop.
    elif type(last.container[-1]) == goto_t and \
            flow.get_block(last.container[-1]) == first:
        
        loop_cls = while_t
        
        # if the very first statement in the first block in the main
        # path is a if_t which jumps out of the loop, then the 
        # condition in the if_t is the loop condition and the goto
        # destination is the exit block.
        if len(first.container) >= 2 and type(first.container[0]) == if_t and \
            type(first.container[0].then_expr[0]) == goto_t and \
            type(first.container[1]) == goto_t and \
            (flow.get_block(first.container[1]) not in all_loop_blocks or 
                flow.get_block(first.container[0].then_expr[0]) not in all_loop_blocks):
            
            left = flow.get_block(first.container[1])
            right = flow.get_block(first.container[0].then_expr[0])
            
            if left not in all_loop_blocks:
                
                exit_block = left
            elif right not in all_loop_blocks:
                
                exit_block = right
                # make sure 'left' is the goto at the end of the block...
                switch_goto_if_needed(first, left)
            
            condition = first.container[0]
            condition_block = first
        else:
            condition = None
        
        # (TODO):
        # in the presence of a while(), if the last block in the 
        # main path contains a statement which shares an expression 
        # operand with the while() conditional expression (either a 
        # regloc_t or var_t or arg_t), or if the very last block has 
        # multiple  paths leading to it (which may be simplified in 
        # a 'continue'), we upgrade the while() to a for() loop.
    
    else:
        # not a loop...
        return False
    
    if condition:
        condition_expr = condition.expr
        flow.remove_goto(condition_block, condition.then_expr[0])
        condition.container.remove(condition)
    else:
        condition_expr = value_t(1, 1)
    
    if not exit_block:
        # here we should choose the best exit block.
        exit_block = choose_exit_block(flow, all_loop_blocks)
    
    # remove goto to the beginning of the loop
    flow.remove_goto(last, last.container[-1])
    
    # join together all blocks on the main path
    first = loop_path[0]
    for block in loop_path[1:]:
        if len(block.jump_from) > 1:
            break
        switch_goto_if_needed(first, block)
        append_block(flow, first, block)
        all_loop_blocks.remove(block)
    
    # change some gotos into breaks and continues
    for block in all_loop_blocks:
        #~ print 'change block', hex(block.ea)
        change_loop_continues(flow, block, block.container, first, exit_block)
    
    # now make a loop of all this...
    
    container = container_t(first.container[:])
    loop = loop_cls(condition_expr, container)
    first.container[:] = [loop, ]
    
    if exit_block:
        first.container.add(goto_t(value_t(exit_block.ea)))
        first.jump_to.append(exit_block)
        exit_block.jump_from.append(first)
    
    #~ print 'after making loop'
    #~ print str(first)
    
    return True

def choose_exit_block(flow, all_blocks):
    
    contenders = []
    
    for b in all_blocks:
        for dst in b.jump_to:
            if dst not in all_blocks and dst not in contenders:
                contenders.append(dst)
    
    print 'exit block contenders:', repr([hex(b.ea) for b in contenders])
    
    return

def combine_loop_paths(flow, path):
    
    blocks = path.longest_path()
    #~ print 'combining path', repr([hex(b.ea) for b in blocks])
    all_loop_blocks = path.all_blocks()
    #~ print 'all blocks', repr([hex(b.ea) for b in all_loop_blocks])
    
    # try to make this into a loop.
    if make_into_loop(flow, blocks, all_loop_blocks):
        return True
    
    return False

def combine_loops_inner(flow, knowns, current):
    
    all_blocks = list(set([b for p in current.paths for b in p]))
    all_blocks.remove(current.origin)
    
    for block in all_blocks:
        path = loop_paths_t(flow, block)
        for known in knowns:
            path.remove_same_paths(known)
        if not path.is_recursive():
            continue
        if combine_loops_inner(flow, knowns[:] + [path, ], path):
            return True
        
        if combine_loop_paths(flow, path):
            return True
    
    return False

def combine_loops(flow, block):
    path = loop_paths_t(flow, block)
    if not path.is_recursive():
        return False
    
    if combine_loops_inner(flow, [path, ], path):
        return True
    
    return combine_loop_paths(flow, path)
__block_filters__.append(combine_loops)

def convert_break_in_container(flow, block, container, goto):
    
    for stmt in container:
        
        if type(stmt) in (while_t, do_while_t):
            # cannot break from inner while to outer while...
            continue
        
        elif type(stmt) == if_t:
            if convert_break_in_container(flow, block, stmt.then_expr, goto):
                return True
            
            if stmt.else_expr:
                if convert_break_in_container(flow, block, stmt.else_expr, goto):
                    return True
        
        elif type(stmt) == goto_t and stmt.expr == goto.expr:
            
            idx = container.index(stmt)
            flow.remove_goto(block, stmt)
            
            container.insert(idx, break_t())
            
            return True
    
    return False

def convert_break(flow, block, container):
    """ in a while_t followed by a goto_t, we can safely replace any instance
        of the same goto_t from inside the loop by a break_t.
    """
    
    for i in range(len(container)-1):
        stmt = container[i]
        goto = container[i+1]
        
        if type(stmt) in (while_t, do_while_t) and type(goto) == goto_t:
            
            return convert_break_in_container(flow, block, stmt.loop_container, goto)
    
    return False
__container_filters__.append(convert_break)

def combine_noreturns(flow, block, container):
    """ if the last call before a goto_t is a noreturn call, 
        then remove the goto_t (which is incorrect anyway). """
    # TODO: the flow code shouldn't put a goto there in the first place.
    
    if len(container) < 2 or type(container[-1]) != goto_t:
        return False
    
    goto = container[-1]
    if type(goto.expr) != value_t or type(container[-2]) != statement_t:
        return False
    
    dst_block = flow.blocks[goto.expr.value]
    
    if type(container[-2].expr) == call_t:
        call = container[-2].expr
    elif type(container[-2].expr) == assign_t and type(container[-2].expr.op2) == call_t:
        call = container[-2].expr.op2
    else:
        return False
    
    if type(call.fct) != value_t:
        return False
    
    if flow.arch.function_does_return(call.fct.value):
        return False
    
    container.remove(goto)
    block.jump_to.remove(dst_block)
    dst_block.jump_from.remove(block)
    
    return True
__container_filters__.append(combine_noreturns)

def combine_block_tail(flow, block, container):
    """ combine goto's with their destination, if the destination has only one path that reaches it """
    
    if len(container) < 1:
        return False
    
    last_stmt = container[-1]
    
    if type(last_stmt) != goto_t or type(last_stmt.expr) != value_t:
        return False
    
    dst_ea = last_stmt.expr.value
    dst_block = flow.blocks[dst_ea]
    
    # check if there is only one jump destination, with the exception of jumps to itself (loops)
    jump_src = [src for src in dst_block.jump_from]
    if len(jump_src) != 1:
        return False
    
    # pop goto
    container.pop()
    
    # extend cur. container with dest container's content
    container.extend(dst_block.container[:])
    block.jump_to += dst_block.jump_to
    
    if dst_block in block.jump_to:
        block.jump_to.remove(dst_block)
    if block in dst_block.jump_from:
        dst_block.jump_from.remove(block)
    
    for to_block in dst_block.jump_to[:]:
        if dst_block in to_block.jump_from:
            to_block.jump_from.remove(dst_block)
        to_block.jump_from.append(block)
    
    block.items += dst_block.items
    
    return True
__container_filters__.append(combine_block_tail)

def combine_else_tails(flow, block, container):
    """ if a block contains an if_t whose then-side ends with the same 
        goto_t as the block itself, then merge all expressions at the 
        end of the block into the else-side of the if_t.
        
        if (...) {
            ...
            goto foo;
        }
        ...
        goto foo;
        
        becomes
        
        if (...) {
           ...
        }
        else {
           ...
        }
        goto foo;
        
        """
    
    for i in range(len(container)):
        stmt = container[i]
        
        while True:
            if type(stmt) == if_t and len(stmt.then_expr) >= 1 and \
                    type(container[-1]) == goto_t and type(stmt.then_expr[-1]) == goto_t and \
                    container[-1] == stmt.then_expr[-1]:
            
                goto = stmt.then_expr.pop(-1)
                dstblock = flow.blocks[goto.expr.value]
                
                block.jump_to.remove(dstblock)
                
                if block in dstblock.jump_from:
                    dstblock.jump_from.remove(block)
                
                stmts = container[i+1:-1]
                container[i+1:-1] = []
                stmt.else_expr = container_t(stmts)
                
                return True
            
            if type(stmt) == if_t and stmt.else_expr and len(stmt.else_expr) == 1 and \
                    type(stmt.else_expr[0]) == if_t:
                stmt = stmt.else_expr[0]
                continue
            
            break
    
    return False
__container_filters__.append(combine_else_tails)

#~ def combine_increments(flow, block, container):
    #~ """ change statements of the type 'a = a + 1' into increment_t """
    
    #~ for stmt in container:
        
        #~ if type(stmt) == statement_t and type(stmt.expr) == assign_t and \
                #~ type(stmt.expr.op2) in (add_t, sub_t) and (stmt.expr.op1 == stmt.expr.op2.op1 \
                #~ and stmt.expr.op2.op2 == value_t(1)):
            
            #~ idx = container.index(stmt)
            #~ _type = inc_t if type(stmt.expr.op2) == add_t else dec_t
            #~ stmt = _type(stmt.expr.op1.copy())
            #~ container[idx] = stmt
            
            #~ return True
    
    #~ return False
#~ __container_filters__.append(combine_increments)

def combine_ifs(flow, block, container):
    """ process if_t """
    
    for stmt in container:
        
        # invert then and else side if then-side is empty
        if type(stmt) == if_t and stmt.else_expr is not None and len(stmt.then_expr) == 0:
            stmt.then_expr = stmt.else_expr
            stmt.expr = b_not_t(stmt.expr.copy())
            stmt.else_expr = None
            
            simplify_expressions.run(stmt.expr, deep=True)
            
            return True
        
        # remove if altogether if it contains no statements at all
        if type(stmt) == if_t and stmt.else_expr is None and len(stmt.then_expr) == 0:
            container.remove(stmt)
            return True
    
    return False
__container_filters__.append(combine_ifs)

def convert_elseif(flow, block, container):
    """ if we have an if_t as only statement in the then-side of a parent 
        if_t, and the parent if_t has an else-side which doesn't contain 
        an if_t as only statement (to avoid infinite loops), then we can 
        safely invert the two sides of the parent if_t so that it will be 
        displayed in the more natural 'if(...) { } else if(...) {}' form.
    """
    
    for stmt in container:
        
        if type(stmt) == if_t and stmt.else_expr and \
                len(stmt.then_expr) == 1 and type(stmt.then_expr[0]) == if_t and \
                not (len(stmt.else_expr) == 1 and type(stmt.else_expr[0]) == if_t): \
            
            stmt.then_expr, stmt.else_expr = stmt.else_expr, stmt.then_expr
            
            stmt.expr = b_not_t(stmt.expr.copy())
            simplify_expressions.run(stmt.expr, deep=True)
            
            return True
    
    return False
__container_filters__.append(convert_elseif)

def combine_container_run(flow, block, container):
    """ process all possible combinations for all containers. """
    
    # first deal with possible nested containers.
    for stmt in container:
        
        if type(stmt) == if_t:
            if combine_container_run(flow, block, stmt.then_expr):
                return True
            if stmt.else_expr:
                if combine_container_run(flow, block, stmt.else_expr):
                    return True
        
        elif type(stmt) in (while_t, do_while_t):
            if combine_container_run(flow, block, stmt.loop_container):
                return True
    
    # apply filters to this container last.
    for filter in __container_filters__:
        if filter(flow, block, container):
            #~ print '---filter---'
            #~ print str(flow)
            #~ print '---filter---'
            return True
    
    return False

def combine_container(flow, block):
    """ process all possible combinations for the top-level container of a block """
    
    return combine_container_run(flow, block, block.container)
__block_filters__.append(combine_container)

def once(flow):
    """ do one combination pass until a single combination is performed. """
    
    for filter in __block_filters__:
        for block in flow.iterblocks():
            if filter(flow, block):
                return True
    
    return False

def run(flow):
    """ combine until no more combinations can be applied. """
    
    while True:
        if not once(flow):
            break
    
    return
