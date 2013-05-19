""" Control flow simplification algorithms.

This file contains algorithms for transforming the control flow into the most
readable form possible.

When the run() routine is called, the control flow is mostly flat, and
consist mostly of normal statements, conditional jump statements of the form
'if(...) goto ...' and unconditional jump statements of the form 'goto ...' 
(without preceding condition). Most of the work done here is applying simple
algorithms to eliminate goto statements.
"""

import idaapi
import idc

import simplify_expressions

from expressions import *
from statements import *

__block_filters__ = [] # filters that are applied to a flow block
__container_filters__ = [] # filters that are applied to a container (i.e. inside a then-branch of an if_t)

def combine_noreturns(flow, block, container):
    """ if the last call before a goto_t is a noreturn call, 
        then remove the goto_t (which is not correct). """
    
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
    
    if not (idc.GetFunctionFlags(call.fct.value) & idaapi.FUNC_NORET):
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
    #~ print 'src', repr([hex(s.ea) for s in jump_src])
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
        goto_t as the block, itself, then merge all expressions at the 
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
        expr = container[i]
        if not (type(expr) == if_t and len(expr.then_expr) >= 1):
            continue
        
        if not (type(container[-1]) == goto_t and type(expr.then_expr[-1]) == goto_t):
            continue
            
        if not (container[-1] == expr.then_expr[-1]):
            continue
        
        goto = expr.then_expr.pop(-1)
        dstblock = flow.blocks[goto.expr.value]
        
        block.jump_to.remove(dstblock)
        
        if block in dstblock.jump_from:
            dstblock.jump_from.remove(block)
        
        stmts = container[i+1:-1]
        container[i+1:-1] = []
        expr.else_expr = container_t(stmts)
        
        return True
    
    return False
__container_filters__.append(combine_else_tails)

def combine_increments(flow, block, container):
    """ change statements of the type 'a = a + 1' into increment_t """
    
    for stmt in container:
        
        if type(stmt) == statement_t and type(stmt.expr) == assign_t and \
                type(stmt.expr.op2) in (add_t, sub_t) and (stmt.expr.op1 == stmt.expr.op2.op1 \
                and stmt.expr.op2.op2 == value_t(1)):
            
            idx = container.index(stmt)
            _type = inc_t if type(stmt.expr.op2) == add_t else dec_t
            stmt = _type(stmt.expr.op1.copy())
            container[idx] = stmt
            
            return True
    
    return False
__container_filters__.append(combine_increments)

def combine_ifs(flow, block, container):
    """ process if_t """
    
    for stmt in container:
        
        # invert then and else side if then-side is empty
        if type(stmt) == if_t and stmt.else_expr is not None and len(stmt.then_expr) == 0:
            stmt.then_expr = stmt.else_expr
            stmt.expr = not_t(stmt.expr)
            stmt.else_expr = None
            
            stmt.expr = simplify_expressions.run(stmt.expr)
            
            return True
        
        # remove if altogether if it contains no statements at all
        if type(stmt) == if_t and stmt.else_expr is None and len(stmt.then_expr) == 0:
            container.remove(stmt)
            return True
    
    return False
__container_filters__.append(combine_ifs)

def combine_if_tail_gotos(flow, block, container):
    """ if two goto statements follow each other with the same goto destination
        at the end of them, then we can remove both goto_t and create a new 
        if_t statement with a single goto_t in it. doing this eliminates one goto.
    
    """
    
    for i in range(len(container)-1):
        first = container[i]
        next = container[i+1]
        
        if not (type(first) == if_t and type(next) == if_t):
            continue
        
        if not (len(first.then_expr) > 0 and len(next.then_expr) > 0):
            continue
        
        if not (type(first.then_expr[-1]) == goto_t and type(next.then_expr[-1]) == goto_t):
            continue
        
        if not (type(first.then_expr[-1].expr) == value_t and type(next.then_expr[-1].expr) == value_t):
            continue
        
        if first.then_expr[-1].expr.value != next.then_expr[-1].expr.value:
            continue
        
        next.then_expr.pop(-1)
        goto = first.then_expr.pop(-1)
        
        # remove one ref to dest block
        block.jump_to.remove(flow.blocks[goto.expr.value])
        flow.blocks[goto.expr.value].jump_from.remove(block)
        
        expr = b_or_t(first.expr.copy(), next.expr.copy())
        stmt = if_t(expr, container_t([goto, ]))
        
        container.insert(i+2, stmt)
        
        return True
    
    return False
__container_filters__.append(combine_if_tail_gotos)

def combine_nested_ifs(flow, block, container):
    """ if two goto statements follow each other with the same goto destination
        at the end of them, then we can remove both goto_t and create a new 
        if_t statement with a single goto_t in it. doing this eliminates one goto.
    
    """
    
    for stmt in container:
        
        if type(stmt) != if_t or len(stmt.then_expr) == 0 or \
                type(stmt.then_expr[-1]) != if_t or stmt.then_expr[-1].else_expr:
            continue
        
        idx = container.index(stmt)
        last = stmt.then_expr.pop(-1)
        
        expr = b_and_t(stmt.expr.copy(), last.expr.copy())
        newstmt = if_t(expr, last.then_expr)
        container.insert(idx+1, newstmt)
        
        return True
    
    # same as above but if_t is the first inner statement
    #~ for stmt in container:
        
        #~ if type(stmt) != if_t or len(stmt.then_expr) == 0 or \
                #~ type(stmt.then_expr[0]) != if_t or stmt.then_expr[0].else_expr:
            #~ continue
        
        #~ idx = container.index(stmt)
        #~ first = stmt.then_expr.pop(0)
        
        #~ expr = b_and_t(stmt.expr.copy(), first.expr.copy())
        #~ newstmt = if_t(expr, first.then_expr)
        #~ container.insert(idx, newstmt)
        
        #~ return True
    
    return False
__container_filters__.append(combine_nested_ifs)

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
            return True
    
    return False

def combine_container(flow, block):
    """ process all possible combinations for the top-level container of a block """
    
    return combine_container_run(flow, block, block.container)
__block_filters__.append(combine_container)

def combine_while(flow, block):
    """ process while_t
    
    a while statement consist of a block with an if_t which contains
    the condition for exiting the loop, and the block contains a goto_t
    as the last statement leading back to the beginning of the block.
    """
    
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
__block_filters__.append(combine_while)

def combine_do_while(flow, block):
    """ process do_while_t
    
    a do-while consist of a if_t which contains a single 
    goto_t statement which jumps back to the beginning of 
    the block.
    """
    
    for i in range(len(block.container)):
        
        stmt = block.container[i]
        
        # only process if_t without else statements.
        if type(stmt) != if_t or stmt.else_expr:
            continue
        
        # only process if_t with a goto as their only statement.
        if len(stmt.then_expr) != 1 or type(stmt.then_expr[0]) != goto_t:
            continue
        
        goto = stmt.then_expr[0]
        
        # ignore if the goto doesn't lead back to this block
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
__block_filters__.append(combine_do_while)

def combine_infinite_while(flow, block):
    """ process while_t(true)
    
    same as normal while(), but this catches the case where there's no 
    if at the beginning nor the end.
    """
    
    if len(block.container) == 0:
        return False
    
    goto = block.container[-1]
    
    if type(goto) != goto_t or type(goto.expr) != value_t:
        return False
    
    if goto.expr.value != block.ea:
        return False
    
    # we have an if_t with a goto as last statement which leads back to this block.
    
    # remove goto
    block.container.pop(-1)
    
    stmts = block.container[:]
    block.container[:] = []
    
    newstmt = while_t(value_t(1), container_t(stmts))
    block.container.insert(0, newstmt)
    
    block.jump_from.remove(block)
    block.jump_to.remove(block)
    
    return True
__block_filters__.append(combine_infinite_while)

def once(flow):
    """ do one combination pass until a single combination is performed. """
    
    for block in flow.iterblocks():
        for filter in __block_filters__:
            if filter(flow, block):
                return True
    
    return False

def run(flow):
    """ combine until no more combinations can be applied. """
    
    while True:
        if not once(flow):
            break
    
    return
