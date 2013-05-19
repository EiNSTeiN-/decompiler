""" Abstracts the logic behind figuring out the arguments to a function call.

http://en.wikipedia.org/wiki/X86_calling_conventions
"""

from expressions import *

class calling_convention(object):
    pass

class systemv_x64_abi(calling_convention):
    """ SystemV AMD64 ABI
    
    The following registers are used to pass arguments: 
        RDI, RSI, RDX, RCX, R8, R9, XMM0-7
    """
    
    def __init__(self):
        
        
        return
    
    def make_call_arguments(self, regs):
        
        if len(regs) == 0:
            return None
        
        regs = regs[:]
        
        arglist = regs.pop(-1)
        while len(regs) > 0:
            arglist = comma_t(regs.pop(-1), arglist)
        
        return arglist
    
    def process(self, flow, block, stmt, call, context):
        
        print 'call', str(call)
        #~ print 'live registers:', repr([str(r) for r, _ in context.context])
        
        # RDI, RSI, RDX, RCX, R8, R9
        which = [7, 6, 2, 1, 8, 9]
        regs = []
        for n in which:
            _pair = context.get_definition(regloc_t(n))
            if not _pair:
                break
            regs.append(_pair[0].copy())
            context.remove_definition(_pair[0])
        
        params = self.make_call_arguments(regs)
        call.params = params
        
        return

