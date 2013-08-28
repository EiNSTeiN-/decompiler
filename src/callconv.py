""" Abstracts the logic behind figuring out the arguments to a function call.

http://en.wikipedia.org/wiki/X86_calling_conventions
"""

from expressions import *
import ir.intel

class calling_convention(object):
    
    def make_call_arguments(self, regs):
        
        if len(regs) == 0:
            return None
        
        regs = regs[:]
        
        arglist = regs.pop(-1)
        while len(regs) > 0:
            arglist = comma_t(regs.pop(-1), arglist)
        
        return arglist
    

class systemv_x64_abi(calling_convention):
    """ SystemV AMD64 ABI
    
    The following registers are used to pass arguments: 
        RDI, RSI, RDX, RCX, R8, R9, XMM0-7
    """
    
    def __init__(self):
        
        
        return
    
    def process(self, flow, ssa_tagger, block, stmt, call):
        
        # RDI, RSI, RDX, RCX, R8, R9
        which = [ir.intel.RDI, ir.intel.RSI, ir.intel.RDX, ir.intel.RCX, ir.intel.R8, ir.intel.R9]
        regs = []
        for n in which:
            
            loc = regloc_t(n, flow.arch.address_size)
            print repr(loc)
            newloc = ssa_tagger.has_internal_definition(stmt, loc)
            if newloc:
                regs.append(newloc.copy())
            elif ssa_tagger.has_contextual_definition(stmt, loc):
                newloc = self.insert_theta(stmt, loc)
                regs.append(newloc.copy())
            else:
                break
        
        params = self.make_call_arguments(regs)
        call.params = params
        
        return
    
    def process_stack(self, flow, block, stmt, call, context):
        
        return

class stdcall(calling_convention):
    """ merge the last few stack assignements to function arguments list.
    """
    
    def __init__(self):
        
        return
    
    def process(self, flow, ssa_tagger, block, stmt, call):
        
        return

